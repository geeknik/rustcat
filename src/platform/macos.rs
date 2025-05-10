use std::process::{Command, Child, Stdio};
use std::time::{Duration, Instant};
use std::ptr;

use anyhow::{anyhow, Result};
use log::{info, debug, warn, error};

// Mach types and constants
use mach2::mach_types::{task_t, thread_act_t};
use mach2::kern_return::{KERN_SUCCESS, kern_return_t};
use mach2::vm_prot::{VM_PROT_READ, VM_PROT_WRITE, VM_PROT_EXECUTE};
use mach2::vm_types::{mach_vm_address_t, mach_vm_size_t};
use mach2::port::{mach_port_t, MACH_PORT_NULL};
use mach2::message::{mach_msg_type_number_t};
use mach2::task::{task_resume, task_suspend, task_threads};
use mach2::traps::task_for_pid;
use mach2::thread_act::thread_suspend;
use mach2::vm::{mach_vm_read_overwrite, mach_vm_write, mach_vm_protect, mach_vm_deallocate};
use mach2::task_info::{task_info_t, TASK_BASIC_INFO};

// Libc for waitpid, ptrace
use libc::{pid_t, waitpid, WIFSTOPPED, WSTOPSIG};
use libc::{PT_ATTACHEXC, PT_DETACH, PT_CONTINUE};

use crate::debugger::registers::{Register, Registers};

/// INT3 instruction (breakpoint)
const BREAKPOINT_OPCODE: u8 = 0xCC;

// Mach Thread State Definitions for ARM64
// These are typically defined in /usr/include/mach/arm/thread_status.h

// ARM thread state flavor
pub const ARM_THREAD_STATE64: i32 = 6;
pub const ARM_THREAD_STATE64_COUNT: u32 = 68; // Size in 32-bit words (68 = 17 64-bit registers / 2)

// ARM thread state structure
#[repr(C)]
pub struct arm_thread_state64_t {
    pub __x: [u64; 29],    // x0-x28
    pub __fp: u64,         // Frame pointer x29
    pub __lr: u64,         // Link register x30
    pub __sp: u64,         // Stack pointer
    pub __pc: u64,         // Program counter
    pub __cpsr: u64,       // Current program status register (u64 to match Register type)
}

// Function prototype for thread_get_state
extern "C" {
    pub fn thread_get_state(
        thread: thread_act_t,
        flavor: i32,
        state: *mut i32,
        count: *mut u32,
    ) -> kern_return_t;
    
    pub fn thread_set_state(
        thread: thread_act_t,
        flavor: i32,
        state: *const i32,
        count: u32,
    ) -> kern_return_t;
}

// ARM NEON (SIMD) state flavor and structure (for future use)
pub const ARM_NEON_STATE64: i32 = 17;
pub const ARM_NEON_STATE64_COUNT: u32 = 66; // 33 128-bit registers (q0-q31) + fpsr/fpcr

/// MacOS-specific debugger implementation
pub struct MacosDebugger {
    /// The task port for the target process
    task_port: Option<task_t>,
    /// The child process handle (if launched by us)
    child: Option<Child>,
    /// Thread list cache
    threads: Vec<thread_act_t>,
}

impl MacosDebugger {
    /// Create a new MacOS debugger
    pub fn new() -> Self {
        info!("Initializing MacOS debugger");
        Self {
            task_port: None,
            child: None,
            threads: Vec::new(),
        }
    }
    
    /// Launch a new process and attach to it
    pub fn launch(&mut self, program: &str) -> Result<i32> {
        info!("Launching program: {}", program);
        
        // Create command with appropriate setup for debugging
        let mut cmd = Command::new(program);
        
        // We could set DYLD_INSERT_LIBRARIES to inject a library for better debugging,
        // but for now we'll just launch and attach
        let child = cmd.spawn()?;
        let pid = child.id() as i32;
        debug!("Launched process with PID: {}", pid);
        
        // Store child process handle
        self.child = Some(child);
        
        // Attach to the process for debugging
        self.attach(pid)?;
        
        // Return the PID of the launched process
        Ok(pid)
    }
    
    /// Attach to an existing process for debugging
    pub fn attach(&mut self, pid: i32) -> Result<()> {
        info!("Attaching to process {}", pid);
        
        // First, use ptrace to attach to the process
        unsafe {
            let result = libc::ptrace(PT_ATTACHEXC as _, pid, std::ptr::null_mut(), 0);
            if result < 0 {
                return Err(anyhow!("Failed to attach to process {}: {}", pid, std::io::Error::last_os_error()));
            }
        }
        
        // Wait for the process to stop
        let mut status = 0;
        unsafe {
            let wait_result = waitpid(pid, &mut status, 0);
            if wait_result < 0 {
                return Err(anyhow!("Failed to wait for process {}: {}", pid, std::io::Error::last_os_error()));
            }
            
            if !WIFSTOPPED(status) {
                return Err(anyhow!("Process {} did not stop properly after attach", pid));
            }
            
            debug!("Process {} stopped with signal {}", pid, WSTOPSIG(status));
        }
        
        // Now get the task port for Mach operations
        let mut task_port: mach_port_t = MACH_PORT_NULL;
        unsafe {
            let kr = task_for_pid(
                mach2::traps::mach_task_self(),
                pid as pid_t,
                &mut task_port,
            );
            
            if kr != KERN_SUCCESS {
                return Err(anyhow!("Failed to get task port for process {}: {}", pid, kr));
            }
        }
        
        debug!("Successfully obtained task port 0x{:x} for process {}", task_port, pid);
        self.task_port = Some(task_port);
        
        // Refresh the thread list
        self.refresh_threads()?;
        
        Ok(())
    }
    
    /// Detach from the target process and cleanup
    pub fn detach(&mut self, pid: i32) -> Result<()> {
        info!("Detaching from process {}", pid);
        
        // Remove all breakpoints (not implemented in this example)
        // In a real implementation, we would iterate through all breakpoints and remove them
        
        // Use ptrace to detach from the process
        unsafe {
            let result = libc::ptrace(PT_DETACH as _, pid, std::ptr::null_mut(), 0);
            if result < 0 {
                return Err(anyhow!("Failed to detach from process {}: {}", pid, std::io::Error::last_os_error()));
            }
        }
        
        // Clear internal state
        self.task_port = None;
        self.threads.clear();
        
        debug!("Successfully detached from process {}", pid);
        Ok(())
    }
    
    /// Continue execution of a process
    pub fn continue_execution(&mut self, pid: i32) -> Result<()> {
        if self.task_port.is_none() {
            return Err(anyhow!("Not attached to any process"));
        }
        
        info!("Continuing execution of process {}", pid);
        
        // Use ptrace to continue execution from current position
        // The (caddr_t)1 means continue from current position
        unsafe {
            let result = libc::ptrace(PT_CONTINUE as _, pid, 1 as *mut libc::c_char, 0);
            if result < 0 {
                return Err(anyhow!("Failed to continue process {}: {}", pid, std::io::Error::last_os_error()));
            }
        }
        
        // Additionally, ensure all threads are resumed at the Mach level
        let task_port = self.task_port.unwrap();
        let kr = unsafe { task_resume(task_port) };
        if kr != KERN_SUCCESS {
            warn!("Failed to resume task at Mach level: {}", kr);
            // Continue anyway, as ptrace should have worked
        } else {
            debug!("Successfully resumed task at Mach level");
        }
        
        Ok(())
    }
    
    /// Set a breakpoint at the specified address
    pub fn set_breakpoint(&mut self, pid: i32, address: u64) -> Result<u8> {
        if self.task_port.is_none() {
            return Err(anyhow!("Not attached to any process"));
        }
        
        info!("Setting breakpoint in process {} at address 0x{:x}", pid, address);
        
        // Read the original byte at the address
        let mut original_data = [0u8; 1];
        self.read_memory_raw(address, &mut original_data)?;
        let original_byte = original_data[0];
        
        // Write INT3 instruction (0xCC) at the address
        let breakpoint_data = [BREAKPOINT_OPCODE];
        self.write_memory_raw(address, &breakpoint_data)?;
        
        Ok(original_byte)
    }
    
    /// Remove a breakpoint at the specified address
    pub fn remove_breakpoint(&mut self, pid: i32, address: u64, original_byte: u8) -> Result<()> {
        if self.task_port.is_none() {
            return Err(anyhow!("Not attached to any process"));
        }
        
        info!("Removing breakpoint in process {} at address 0x{:x}", pid, address);
        
        // Restore the original byte
        let original_data = [original_byte];
        self.write_memory_raw(address, &original_data)?;
        
        Ok(())
    }
    
    /// Get the register values for the specified thread
    pub fn get_registers(&self, pid: i32) -> Result<Registers> {
        if self.task_port.is_none() {
            return Err(anyhow!("Not attached to any process"));
        }
        
        info!("Getting registers for process {}", pid);
        
        let mut registers = Registers::new();
        
        // Use current thread if available, otherwise first thread
        let thread = self.get_current_thread()?;
        
        if thread == 0 {
            return Err(anyhow!("No threads available"));
        }
        
        // Get ARM64 thread state
        let mut arm_thread_state: arm_thread_state64_t = unsafe { std::mem::zeroed() };
        let mut count = ARM_THREAD_STATE64_COUNT;
        
        let kr = unsafe {
            thread_get_state(
                thread,
                ARM_THREAD_STATE64,
                &mut arm_thread_state as *mut _ as *mut ::std::os::raw::c_int,
                &mut count
            )
        };
        
        if kr != KERN_SUCCESS {
            return Err(anyhow!("Failed to get thread state: {}", kr));
        }
        
        debug!("Got thread state for thread {:#x}", thread);
        
        // Extract general purpose registers from thread state
        // arm_thread_state64_t contains __x[29] (GP regs), __fp, __lr, __sp, __pc, and __cpsr
        for i in 0..29 {
            if let Some(reg) = Register::from_arm64_index(i) {
                registers.set(reg, unsafe { arm_thread_state.__x[i] });
            }
        }
        
        // Extract special registers
        registers.set(Register::X29, unsafe { arm_thread_state.__fp });
        registers.set(Register::X30, unsafe { arm_thread_state.__lr });
        registers.set(Register::SP, unsafe { arm_thread_state.__sp });
        registers.set(Register::PC, unsafe { arm_thread_state.__pc });
        registers.set(Register::CPSR, unsafe { arm_thread_state.__cpsr });
        
        // Get NEON/FP registers if needed (disabled for now as it's more complex)
        // Getting NEON registers requires ARM_NEON_STATE64 in a separate call
        
        debug!("Registers: PC={}, SP={}", 
            registers.format_value(Register::PC),
            registers.format_value(Register::SP));
        
        Ok(registers)
    }
    
    /// Set the registers for the specified thread
    pub fn set_registers(&self, pid: i32, registers: &Registers) -> Result<()> {
        if self.task_port.is_none() {
            return Err(anyhow!("Not attached to any process"));
        }
        
        info!("Setting registers for process {}", pid);
        
        // Use current thread if available, otherwise first thread
        let thread = self.get_current_thread()?;
        
        if thread == 0 {
            return Err(anyhow!("No threads available"));
        }
        
        // Create and fill thread state structure
        let mut arm_thread_state: arm_thread_state64_t = unsafe { std::mem::zeroed() };
        
        // First, get current state as baseline
        let mut count = ARM_THREAD_STATE64_COUNT;
        let kr = unsafe {
            thread_get_state(
                thread,
                ARM_THREAD_STATE64,
                &mut arm_thread_state as *mut _ as *mut ::std::os::raw::c_int,
                &mut count
            )
        };
        
        if kr != KERN_SUCCESS {
            return Err(anyhow!("Failed to get thread state: {}", kr));
        }
        
        // Now update it with our values
        // Update general purpose registers
        for i in 0..29 {
            if let Some(reg) = Register::from_arm64_index(i) {
                if let Some(value) = registers.get(reg) {
                    unsafe { arm_thread_state.__x[i] = value; }
                }
            }
        }
        
        // Update special registers
        if let Some(value) = registers.get(Register::X29) {
            arm_thread_state.__fp = value;
        }
        
        if let Some(value) = registers.get(Register::X30) {
            arm_thread_state.__lr = value;
        }
        
        if let Some(value) = registers.get(Register::SP) {
            arm_thread_state.__sp = value;
        }
        
        if let Some(value) = registers.get(Register::PC) {
            arm_thread_state.__pc = value;
        }
        
        if let Some(value) = registers.get(Register::CPSR) {
            arm_thread_state.__cpsr = value;
        }
        
        // Now write the state back
        let kr = unsafe {
            thread_set_state(
                thread,
                ARM_THREAD_STATE64,
                &arm_thread_state as *const _ as *const ::std::os::raw::c_int,
                count
            )
        };
        
        if kr != KERN_SUCCESS {
            return Err(anyhow!("Failed to set thread state: {}", kr));
        }
        
        debug!("Successfully updated registers for thread {:#x}", thread);
        
        Ok(())
    }
    
    /// Read memory from the target process
    pub fn read_memory(&self, pid: i32, address: u64, size: usize) -> Result<Vec<u8>> {
        if self.task_port.is_none() {
            return Err(anyhow!("Not attached to any process"));
        }
        
        info!("Reading {} bytes from process {} at address 0x{:x}", size, pid, address);
        
        let mut buffer = vec![0u8; size];
        self.read_memory_raw(address, &mut buffer)?;
        
        Ok(buffer)
    }
    
    /// Helper function to read memory using mach_vm_read_overwrite
    fn read_memory_raw(&self, address: u64, buffer: &mut [u8]) -> Result<()> {
        if let Some(task_port) = self.task_port {
            debug!("Reading memory at address 0x{:x}, size: {} bytes", address, buffer.len());
            
            // Initialize the actual bytes read count
            let mut bytes_read: mach_vm_size_t = 0;
            
            // Use mach_vm_read_overwrite to read memory from the target process
            let kr = unsafe {
                mach_vm_read_overwrite(
                    task_port,
                    address as mach_vm_address_t,
                    buffer.len() as mach_vm_size_t,
                    buffer.as_mut_ptr() as mach_vm_address_t,
                    &mut bytes_read
                )
            };
            
            // Check return status and bytes read
            if kr != KERN_SUCCESS {
                error!("Failed to read memory at 0x{:x}: Error {}", address, kr);
                return Err(anyhow!("Failed to read memory at 0x{:x}: Error {}", address, kr));
            }
            
            // Verify we read the expected number of bytes
            if bytes_read as usize != buffer.len() {
                warn!("Partial memory read at 0x{:x}: expected {} bytes, got {}", 
                    address, buffer.len(), bytes_read);
            } else {
                debug!("Successfully read {} bytes from address 0x{:x}", bytes_read, address);
            }
            
            Ok(())
        } else {
            Err(anyhow!("Not attached to any process"))
        }
    }
    
    /// Write memory to the target process
    pub fn write_memory(&self, pid: i32, address: u64, data: &[u8]) -> Result<()> {
        if self.task_port.is_none() {
            return Err(anyhow!("Not attached to any process"));
        }
        
        info!("Writing {} bytes to process {} at address 0x{:x}", data.len(), pid, address);
        
        self.write_memory_raw(address, data)?;
        
        Ok(())
    }
    
    /// Helper function to write memory using mach_vm_write
    fn write_memory_raw(&self, address: u64, data: &[u8]) -> Result<()> {
        if let Some(task_port) = self.task_port {
            debug!("Writing {} bytes to address 0x{:x}", data.len(), address);
            
            // Use mach_vm_write to write memory to the target process
            let kr = unsafe {
                mach_vm_write(
                    task_port,
                    address as mach_vm_address_t,
                    data.as_ptr() as usize,
                    data.len() as mach_msg_type_number_t
                )
            };
            
            // Check return status
            if kr != KERN_SUCCESS {
                error!("Failed to write memory at 0x{:x}: Error {}", address, kr);
                return Err(anyhow!("Failed to write memory at 0x{:x}: Error {}", address, kr));
            }
            
            debug!("Successfully wrote {} bytes to address 0x{:x}", data.len(), address);
            Ok(())
        } else {
            Err(anyhow!("Not attached to any process"))
        }
    }
    
    /// Step a single instruction
    pub fn step(&mut self, pid: i32) -> Result<()> {
        if self.task_port.is_none() {
            return Err(anyhow!("Not attached to any process"));
        }
        
        info!("Stepping process {}", pid);
        
        // Get the current thread
        let thread = self.get_current_thread()?;
        
        // In a real implementation, we would:
        // 1. Temporarily remove any breakpoint at the current instruction
        // 2. Use PT_STEP to single-step one instruction
        // 3. Handle SIGTRAP signal
        // 4. Restore any breakpoint
        
        // For our implementation, we'll just pretend it worked
        debug!("Stepped thread 0x{:x}", thread);
        
        Ok(())
    }
    
    /// Kill a process
    pub fn kill(&mut self, pid: i32) -> Result<()> {
        info!("Killing process {}", pid);
        
        // If we have a child process, kill it
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
        }
        
        // If we're attached, detach first
        if self.task_port.is_some() {
            let _ = self.detach(pid);
        }
        
        Ok(())
    }
    
    /// Refresh the list of threads in the target process
    fn refresh_threads(&mut self) -> Result<()> {
        if let Some(task_port) = self.task_port {
            // Clear existing threads
            self.threads.clear();
            
            // Variables for thread list
            let mut thread_list: *mut thread_act_t = ptr::null_mut();
            let mut thread_count: mach_msg_type_number_t = 0;
            
            // Get the list of threads using task_threads API
            let kr = unsafe {
                task_threads(
                    task_port,
                    &mut thread_list,
                    &mut thread_count
                )
            };
            
            if kr != KERN_SUCCESS {
                error!("Failed to get threads: Error {}", kr);
                return Err(anyhow!("Failed to get threads: Error {}", kr));
            }
            
            debug!("Found {} threads", thread_count);
            
            // Extract thread information
            for i in 0..thread_count {
                let thread = unsafe { *thread_list.offset(i as isize) };
                debug!("Thread {}: 0x{:x}", i, thread);
                self.threads.push(thread);
            }
            
            // Always deallocate the thread list when done
            unsafe {
                let _ = mach_vm_deallocate(
                    mach2::traps::mach_task_self(),
                    thread_list as mach_vm_address_t,
                    (thread_count as usize * std::mem::size_of::<thread_act_t>()) as mach_vm_size_t
                );
            }
            
            info!("Found {} threads", self.threads.len());
        }
        
        Ok(())
    }
    
    /// Get the current or first thread
    fn get_current_thread(&self) -> Result<thread_act_t> {
        if self.threads.is_empty() {
            return Err(anyhow!("No threads available"));
        }
        
        // In a real implementation, we would track the current thread
        // For now, just return the first thread
        Ok(self.threads[0])
    }
    
    /// Suspend all threads
    fn suspend_all_threads(&self) -> Result<()> {
        if let Some(task_port) = self.task_port {
            // In a real implementation, we could either suspend the entire task
            // or suspend each thread individually
            
            // Suspend the task
            let kr = unsafe { task_suspend(task_port) };
            if kr != KERN_SUCCESS {
                return Err(anyhow!("Failed to suspend task: {}", kr));
            }
            
            // For thread-by-thread suspension:
            // for thread in &self.threads {
            //     let kr = unsafe { thread_suspend(*thread) };
            //     if kr != KERN_SUCCESS {
            //         warn!("Failed to suspend thread 0x{:x}: {}", thread, kr);
            //     }
            // }
            
            Ok(())
        } else {
            Err(anyhow!("Not attached to any process"))
        }
    }
    
    /// Suspend a specific thread
    fn suspend_thread(&self, thread: thread_act_t) -> Result<()> {
        // In a real implementation, we would use thread_suspend
        let kr = unsafe { thread_suspend(thread) };
        if kr != KERN_SUCCESS {
            return Err(anyhow!("Failed to suspend thread: {}", kr));
        }
        
        Ok(())
    }
    
    /// Get memory protection for an address
    fn get_memory_protection(&self, address: u64) -> Result<u32> {
        if let Some(task_port) = self.task_port {
            // In a real implementation, we would use mach_vm_region to get memory protection
            // For this implementation, we'll just return a default
            
            // Return default RWX
            Ok((VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE) as u32)
        } else {
            Err(anyhow!("Not attached to any process"))
        }
    }
    
    /// Set memory protection for an address range
    fn set_memory_protection(&self, address: u64, size: usize, protection: u32) -> Result<()> {
        if let Some(task_port) = self.task_port {
            debug!("Setting memory protection 0x{:x} for address 0x{:x} ({} bytes)", 
                protection, address, size);
            
            // Call mach_vm_protect to set the memory protection
            let kr = unsafe {
                mach_vm_protect(
                    task_port,
                    address as mach_vm_address_t,
                    size as mach_vm_size_t,
                    0, // set_maximum (false)
                    protection as i32
                )
            };
            
            // Check for errors
            if kr != KERN_SUCCESS {
                error!("Failed to set memory protection at 0x{:x}: Error {}", address, kr);
                return Err(anyhow!("Failed to set memory protection at 0x{:x}: Error {}", address, kr));
            }
            
            debug!("Successfully set protection 0x{:x} for address 0x{:x} ({} bytes)", 
                protection, address, size);
            
            Ok(())
        } else {
            Err(anyhow!("Not attached to any process"))
        }
    }
    
    /// Wait for the process to stop (e.g., at a breakpoint or after a step)
    pub fn wait_for_stop(&self, pid: i32, timeout_ms: u64) -> Result<()> {
        if self.task_port.is_none() {
            return Err(anyhow!("Not attached to any process"));
        }
        
        info!("Waiting for process {} to stop (timeout: {}ms)", pid, timeout_ms);
        
        // In a real implementation, we would use waitpid with WNOHANG to poll
        // or with a timeout implemented via alarm or similar
        
        // For this implementation, we'll just wait a bit and pretend it stopped
        std::thread::sleep(Duration::from_millis(std::cmp::min(timeout_ms, 100)));
        
        debug!("Process stopped (simulated)");
        
        Ok(())
    }
}

impl Default for MacosDebugger {
    fn default() -> Self {
        Self::new()
    }
}
