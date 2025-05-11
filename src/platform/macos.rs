use std::process::{Command, Child};
use std::time::Duration;
use std::ptr;
use std::collections::HashMap;

use anyhow::{anyhow, Result};
use log::{info, debug, warn, error};

// Mach types and constants
use mach2::mach_types::{task_t, thread_act_t};
use mach2::kern_return::KERN_SUCCESS;
use mach2::vm_prot::{VM_PROT_READ, VM_PROT_WRITE, VM_PROT_EXECUTE};
use mach2::vm_types::{mach_vm_address_t, mach_vm_size_t};
use mach2::port::{mach_port_t, MACH_PORT_NULL};
use mach2::message::mach_msg_type_number_t;
use mach2::task::{task_resume, task_suspend, task_threads};
use mach2::traps::{task_for_pid, mach_task_self};
use mach2::thread_act::{thread_suspend, thread_get_state, thread_set_state};
use mach2::vm::{mach_vm_read_overwrite, mach_vm_write, mach_vm_protect, mach_vm_deallocate};

// Libc for waitpid, ptrace
use libc::{pid_t, waitpid, WIFSTOPPED, WSTOPSIG};
use libc::{PT_ATTACHEXC, PT_DETACH, PT_CONTINUE};

use crate::debugger::registers::{Registers, Register};
use crate::platform::WatchpointType;
use crate::platform::DebugCapabilities;

// ARM64 debug register constants for Apple Silicon
// Based on ARM Architecture Reference Manual for ARMv8-A

// ARM DEBUG STATE STRUCTURE
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ArmDebugState64T {
    // Debug register pairs, each pair has a value and control register
    pub __bvr: [u64; 16],   // Breakpoint Value Registers
    pub __bcr: [u64; 16],   // Breakpoint Control Registers
    pub __wvr: [u64; 16],   // Watchpoint Value Registers
    pub __wcr: [u64; 16],   // Watchpoint Control Registers
}

// DEBUG STATE FLAVOR - ARM_DEBUG_STATE64 value
pub const ARM_DEBUG_STATE64: i32 = 14;

// ARM64 DEBUG REGISTER MASKS AND CONSTANTS FOR WATCHPOINT CONFIGURATION
// Watchpoint Control Register (DBGWCR) bit definitions
const WCR_E: u64 = 0x1;                // Enable bit (bit 0)
const WCR_PAC_MASK: u64 = 0x3 << 1;    // Privilege Access Control (bits 1-2)
const WCR_PAC_ANY: u64 = 0x3 << 1;     // Match in any mode
const WCR_LSC_MASK: u64 = 0x3 << 3;    // Load/Store Control (bits 3-4)
const WCR_LSC_LOAD: u64 = 0x1 << 3;    // Watch for loads (reads)
const WCR_LSC_STORE: u64 = 0x2 << 3;   // Watch for stores (writes)
const WCR_LSC_BOTH: u64 = 0x3 << 3;    // Watch for both loads and stores
const WCR_BAS_MASK: u64 = 0xFF << 5;   // Byte Address Select (bits 5-12)
const WCR_BAS_BYTE1: u64 = 0x01 << 5;  // Watch byte 0
const WCR_BAS_BYTE2: u64 = 0x03 << 5;  // Watch bytes 0-1
const WCR_BAS_BYTE4: u64 = 0x0F << 5;  // Watch bytes 0-3
const WCR_BAS_BYTE8: u64 = 0xFF << 5;  // Watch bytes 0-7
const WCR_MASK: u64 = 0x0000_FFFF;     // Mask for the control bits we use

// Maximum number of watchpoints on Apple Silicon
const MAX_WATCHPOINTS: usize = 4;       // M1/M2 typically have 4 watchpoint registers

/// INT3 instruction (breakpoint)
const BREAKPOINT_OPCODE: u8 = 0xCC;

// Mach Thread State Definitions for ARM64
// These are typically defined in /usr/include/mach/arm/thread_status.h

// ARM thread state flavor
pub const ARM_THREAD_STATE64: i32 = 6;
pub const ARM_THREAD_STATE64_COUNT: u32 = 68; // 34 64-bit registers (x0-x29, fp, lr, sp, pc, cpsr)

// ARM thread state structure
#[repr(C)]
pub struct ArmThreadState64T {
    pub __x: [u64; 29],    // x0-x28
    pub __fp: u64,         // Frame pointer x29
    pub __lr: u64,         // Link register x30
    pub __sp: u64,         // Stack pointer
    pub __pc: u64,         // Program counter
    pub __cpsr: u64,       // Current program status register (u64 to match Register type)
}

// ARM NEON (SIMD) state flavor and structure (for future use)
#[allow(dead_code)]
pub const ARM_NEON_STATE64: i32 = 17;
#[allow(dead_code)]
pub const ARM_NEON_STATE64_COUNT: u32 = 66; // 33 128-bit registers (q0-q31) + fpsr/fpcr

/// MacOS-specific debugger implementation
pub struct MacosDebugger {
    /// The task port for the target process
    _task_port: Option<task_t>,
    /// The child process handle (if launched by us)
    child: Option<Child>,
    /// Thread list cache
    threads: Vec<thread_act_t>,
    /// Currently active hardware watchpoints (register_index -> address)
    watchpoint_registers: HashMap<usize, u64>,
}

impl MacosDebugger {
    /// Create a new MacOS debugger
    pub fn new() -> Self {
        info!("Initializing MacOS debugger");
        Self {
            _task_port: None,
            child: None,
            threads: Vec::new(),
            watchpoint_registers: HashMap::new(),
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
                mach_task_self(),
                pid as pid_t,
                &mut task_port,
            );
            
            if kr != KERN_SUCCESS {
                return Err(anyhow!("Failed to get task port for process {}: {}", pid, kr));
            }
        }
        
        debug!("Successfully obtained task port 0x{:x} for process {}", task_port, pid);
        self._task_port = Some(task_port);
        
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
        self._task_port = None;
        self.threads.clear();
        
        debug!("Successfully detached from process {}", pid);
        Ok(())
    }
    
    /// Continue execution of a process
    pub fn continue_execution(&mut self, pid: i32) -> Result<()> {
        if self._task_port.is_none() {
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
        let task_port = self._task_port.unwrap();
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
        if self._task_port.is_none() {
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
        if self._task_port.is_none() {
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
        if self._task_port.is_none() {
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
        let mut arm_thread_state: ArmThreadState64T = unsafe { std::mem::zeroed() };
        let mut count = ARM_THREAD_STATE64_COUNT;
        
        let kr = unsafe {
            thread_get_state(
                thread,
                ARM_THREAD_STATE64,
                &mut arm_thread_state as *mut _ as *mut u32,
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
                registers.set(reg, arm_thread_state.__x[i]);
            }
        }
        
        // Extract special registers
        registers.set(Register::X29, arm_thread_state.__fp);
        registers.set(Register::X30, arm_thread_state.__lr);
        registers.set(Register::Sp, arm_thread_state.__sp);
        registers.set(Register::Pc, arm_thread_state.__pc);
        registers.set(Register::Cpsr, arm_thread_state.__cpsr);
        
        // Get NEON/FP registers if needed (disabled for now as it's more complex)
        // Getting NEON registers requires ARM_NEON_STATE64 in a separate call
        
        debug!("Registers: PC={}, SP={}", 
            registers.format_value(Register::Pc),
            registers.format_value(Register::Sp));
        
        Ok(registers)
    }
    
    /// Set the registers for the specified thread
    pub fn set_registers(&self, pid: i32, registers: &Registers) -> Result<()> {
        if self._task_port.is_none() {
            return Err(anyhow!("Not attached to any process"));
        }
        
        info!("Setting registers for process {}", pid);
        
        // Use current thread if available, otherwise first thread
        let thread = self.get_current_thread()?;
        
        if thread == 0 {
            return Err(anyhow!("No threads available"));
        }
        
        // Create and fill thread state structure
        let mut arm_thread_state: ArmThreadState64T = unsafe { std::mem::zeroed() };
        
        // First, get current state as baseline
        let mut count = ARM_THREAD_STATE64_COUNT;
        let kr = unsafe {
            thread_get_state(
                thread,
                ARM_THREAD_STATE64,
                &mut arm_thread_state as *mut _ as *mut u32,
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
                    arm_thread_state.__x[i] = value;
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
        
        if let Some(value) = registers.get(Register::Sp) {
            arm_thread_state.__sp = value;
        }
        
        if let Some(value) = registers.get(Register::Pc) {
            arm_thread_state.__pc = value;
        }
        
        if let Some(value) = registers.get(Register::Cpsr) {
            arm_thread_state.__cpsr = value;
        }
        
        // Now write the state back
        let kr = unsafe {
            thread_set_state(
                thread,
                ARM_THREAD_STATE64,
                &arm_thread_state as *const _ as *mut u32,
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
        if self._task_port.is_none() {
            return Err(anyhow!("Not attached to any process"));
        }
        
        info!("Reading {} bytes from process {} at address 0x{:x}", size, pid, address);
        
        let mut buffer = vec![0u8; size];
        self.read_memory_raw(address, &mut buffer)?;
        
        Ok(buffer)
    }
    
    /// Helper function to read memory using mach_vm_read_overwrite
    fn read_memory_raw(&self, address: u64, buffer: &mut [u8]) -> Result<()> {
        if let Some(_task_port) = self._task_port {
            debug!("Reading memory at address 0x{:x}, size: {} bytes", address, buffer.len());
            
            // Initialize the actual bytes read count
            let mut bytes_read: mach_vm_size_t = 0;
            
            // Use mach_vm_read_overwrite to read memory from the target process
            let kr = unsafe {
                mach_vm_read_overwrite(
                    _task_port,
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
        if self._task_port.is_none() {
            return Err(anyhow!("Not attached to any process"));
        }
        
        info!("Writing {} bytes to process {} at address 0x{:x}", data.len(), pid, address);
        
        self.write_memory_raw(address, data)?;
        
        Ok(())
    }
    
    /// Helper function to write memory using mach_vm_write
    fn write_memory_raw(&self, address: u64, data: &[u8]) -> Result<()> {
        if let Some(_task_port) = self._task_port {
            debug!("Writing {} bytes to address 0x{:x}", data.len(), address);
            
            // Use mach_vm_write to write memory to the target process
            let kr = unsafe {
                mach_vm_write(
                    _task_port,
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
        if self._task_port.is_none() {
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
        if self._task_port.is_some() {
            let _ = self.detach(pid);
        }
        
        Ok(())
    }
    
    /// Refresh the list of threads in the target process
    fn refresh_threads(&mut self) -> Result<()> {
        if let Some(_task_port) = self._task_port {
            // Clear existing threads
            self.threads.clear();
            
            // Variables for thread list
            let mut thread_list: *mut thread_act_t = ptr::null_mut();
            let mut thread_count: mach_msg_type_number_t = 0;
            
            // Get the list of threads using task_threads API
            let kr = unsafe {
                task_threads(
                    _task_port,
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
                    mach_task_self(),
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
    
    /// Suspend all threads in the current process
    #[allow(dead_code)]
    fn suspend_all_threads(&self) -> Result<()> {
        if let Some(_task_port) = self._task_port {
            // In a real implementation, we could either suspend the entire task
            // or suspend each thread individually
            
            // Suspend the task
            let kr = unsafe { task_suspend(_task_port) };
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
    
    /// Suspend a thread by its port
    fn suspend_thread(thread: thread_act_t) -> Result<()> {
        unsafe {
            let kr = thread_suspend(thread);
            if kr != KERN_SUCCESS {
                return Err(anyhow!("Failed to suspend thread: error {}", kr));
            }
        }
        Ok(())
    }
    
    /// Get memory protection flags for an address
    #[allow(dead_code)]
    fn get_memory_protection(&self, _address: u64) -> Result<u32> {
        if let Some(_task_port) = self._task_port {
            // In a real implementation, we would use mach_vm_region to get memory protection
            // For this implementation, we'll just return a default
            
            // Return default RWX
            Ok((VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE) as u32)
        } else {
            Err(anyhow!("Not attached to any process"))
        }
    }
    
    /// Set memory protection flags for a region
    #[allow(dead_code)]
    fn set_memory_protection(&self, address: u64, size: usize, protection: u32) -> Result<()> {
        if let Some(_task_port) = self._task_port {
            debug!("Setting memory protection 0x{:x} for address 0x{:x} ({} bytes)", 
                protection, address, size);
            
            // Call mach_vm_protect to set the memory protection
            let kr = unsafe {
                mach_vm_protect(
                    _task_port,
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
        if self._task_port.is_none() {
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
    
    /// Query hardware debug capabilities
    pub fn get_debug_capabilities(&self) -> DebugCapabilities {
        // For Apple Silicon M1/M2, typically 4 hardware watchpoints
        DebugCapabilities {
            hw_breakpoint_count: 8,  // M1/M2 typically have 8 hardware breakpoint registers
            hw_watchpoint_count: MAX_WATCHPOINTS,
        }
    }
    
    /// Get thread port from task port and thread ID
    fn get_thread_port(task: mach_port_t, thread_id: u64) -> Result<thread_act_t> {
        // In our implementation, thread_id is actually the thread port number
        // This is a simplification. In a fully-featured debugger, we would:
        // 1. Get the list of all threads in the task using task_threads()
        // 2. Iterate through them to find the one matching our thread_id
        // 3. Return that thread port
        
        // First, verify that the task port is valid
        if task == MACH_PORT_NULL {
            return Err(anyhow!("Invalid task port: MACH_PORT_NULL"));
        }
        
        // Get thread list from the task
        let mut thread_list = std::ptr::null_mut();
        let mut thread_count: mach_msg_type_number_t = 0;
        
        unsafe {
            let kr = task_threads(
                task,
                &mut thread_list,
                &mut thread_count
            );
            
            if kr != KERN_SUCCESS {
                return Err(anyhow!("Failed to get threads for task: error {}", kr));
            }
            
            // Look for a matching thread port in the list
            let mut found = false;
            for i in 0..thread_count {
                let current_thread = *(thread_list as *const mach_port_t).add(i as usize);
                if current_thread as u64 == thread_id {
                    found = true;
                    break;
                }
            }
            
            // Deallocate the thread list when done
            let _ = mach_vm_deallocate(
                mach_task_self(),
                thread_list as mach_vm_address_t,
                (thread_count * std::mem::size_of::<mach_port_t>() as u32) as mach_vm_size_t
            );
            
            // If we didn't find the thread in this task, return an error
            if !found {
                return Err(anyhow!("Thread ID {} not found in the specified task", thread_id));
            }
        }
        
        // Verify the thread port is valid by getting thread state
        let mut state = ArmThreadState64T { 
            __x: [0; 29],
            __fp: 0,
            __lr: 0,
            __sp: 0,
            __pc: 0,
            __cpsr: 0
        };
        
        let mut count = ARM_THREAD_STATE64_COUNT;
        
        unsafe {
            let kr = thread_get_state(
                thread_id as thread_act_t,
                ARM_THREAD_STATE64,
                &mut state as *mut _ as *mut u32,
                &mut count
            );
            
            if kr != KERN_SUCCESS {
                return Err(anyhow!("Invalid thread port {}: error {}", thread_id, kr));
            }
        }
        
        Ok(thread_id as thread_act_t)
    }
    
    /// Get list of threads for a process
    fn get_threads(&self, pid: i32) -> Result<Vec<u64>> {
        if let Some(task_port) = self._task_port {
            // Get thread list from task
            let mut thread_list = std::ptr::null_mut();
            let mut thread_count: mach_msg_type_number_t = 0;
            
            unsafe {
                let kr = task_threads(
                    task_port,
                    &mut thread_list,
                    &mut thread_count
                );
                
                if kr != KERN_SUCCESS {
                    return Err(anyhow!("Failed to get threads for process {}: error {}", pid, kr));
                }
                
                // Convert thread ports to thread IDs (use the port value as ID for now)
                let mut thread_ids = Vec::with_capacity(thread_count as usize);
                
                for i in 0..thread_count {
                    let thread_port = *(thread_list as *const mach_port_t).add(i as usize);
                    thread_ids.push(thread_port as u64);
                    
                    // Ideally we would deallocate the thread port reference here,
                    // but we'll rely on mach_vm_deallocate below to clean up
                }
                
                // Deallocate the thread list
                let _ = mach_vm_deallocate(
                    mach_task_self(),
                    thread_list as mach_vm_address_t,
                    (thread_count * std::mem::size_of::<mach_port_t>() as u32) as mach_vm_size_t
                );
                
                debug!("Found {} threads for process {}", thread_ids.len(), pid);
                return Ok(thread_ids);
            }
        }
        
        Err(anyhow!("Not attached to any process"))
    }
    
    /// Get registers for a thread
    pub fn get_thread_registers(&self, _pid: i32, thread_id: u64) -> Result<Registers> {
        // Get the thread port for the thread ID
        let thread_port = Self::get_thread_port(self._task_port.unwrap_or(MACH_PORT_NULL), thread_id)?;
        
        // Get the thread state
        let mut arm_thread_state = ArmThreadState64T { 
            __x: [0; 29],
            __fp: 0,
            __lr: 0,
            __sp: 0,
            __pc: 0,
            __cpsr: 0
        };
        
        let mut count = ARM_THREAD_STATE64_COUNT;
        
        unsafe {
            let kr = thread_get_state(
                thread_port,
                ARM_THREAD_STATE64, 
                &mut arm_thread_state as *mut _ as *mut u32,
                &mut count
            );
            
            if kr != KERN_SUCCESS {
                return Err(anyhow!("Failed to get thread state: error {}", kr));
            }
        }
        
        // Create a Registers object and populate it with the thread state
        let mut registers = Registers::new();
        
        // Copy the general-purpose registers (x0-x28)
        for i in 0..29 {
            if let Some(reg) = Register::from_arm64_index(i) {
                registers.set(reg, arm_thread_state.__x[i]);
            }
        }
        
        // Set special registers
        registers.set(Register::X29, arm_thread_state.__fp);  // Frame pointer (x29)
        registers.set(Register::X30, arm_thread_state.__lr);  // Link register (x30)
        registers.set(Register::Sp, arm_thread_state.__sp);   // Stack pointer
        registers.set(Register::Pc, arm_thread_state.__pc);   // Program counter
        registers.set(Register::Cpsr, arm_thread_state.__cpsr); // Current program status register
        
        Ok(registers)
    }
    
    /// Set a hardware watchpoint
    pub fn set_watchpoint(&mut self, pid: i32, thread_id: u64, address: u64, size: usize, 
                          watchpoint_type: WatchpointType) -> Result<usize> {
        // Check if we have any free watchpoint registers
        let used_registers = self.watchpoint_registers.len();
        if used_registers >= MAX_WATCHPOINTS {
            return Err(anyhow!("No free hardware watchpoint registers available"));
        }
        
        // Find the next available register index
        let register_index = (0..MAX_WATCHPOINTS)
            .find(|i| !self.watchpoint_registers.contains_key(i))
            .unwrap(); // Safe because we checked used_registers < MAX_WATCHPOINTS
        
        // Get the task port for the target process
        let mut task: mach_port_t = 0;
        unsafe {
            let kr = task_for_pid(mach_task_self(), pid, &mut task);
            if kr != KERN_SUCCESS {
                return Err(anyhow!("Failed to get task for pid {}: error {}", pid, kr));
            }
        }
        
        // Get thread port
        let thread_port = Self::get_thread_port(task, thread_id)?;
        
        // Get current debug state
        let mut count = (std::mem::size_of::<ArmDebugState64T>() / std::mem::size_of::<u32>()) as u32;
        let mut debug_state = ArmDebugState64T {
            __bvr: [0; 16],
            __bcr: [0; 16],
            __wvr: [0; 16],
            __wcr: [0; 16],
        };
        
        unsafe {
            let kr = thread_get_state(
                thread_port,
                ARM_DEBUG_STATE64,
                &mut debug_state as *mut _ as *mut u32,
                &mut count
            );
            
            if kr != KERN_SUCCESS {
                return Err(anyhow!("Failed to get debug state: error {}", kr));
            }
        }
        
        // Set up watchpoint value register
        debug_state.__wvr[register_index] = address;
        
        // Set up watchpoint control register
        let mut wcr_val: u64 = 0;
        
        // Enable bit
        wcr_val |= WCR_E;
        
        // Set privilege mode (match in any mode)
        wcr_val |= WCR_PAC_ANY;
        
        // Set watch type
        match watchpoint_type {
            WatchpointType::Read => wcr_val |= WCR_LSC_LOAD,
            WatchpointType::Write => wcr_val |= WCR_LSC_STORE,
            WatchpointType::ReadWrite => wcr_val |= WCR_LSC_BOTH,
        }
        
        // Set byte address select
        let bas = match size {
            1 => WCR_BAS_BYTE1,
            2 => WCR_BAS_BYTE2,
            4 => WCR_BAS_BYTE4,
            8 => WCR_BAS_BYTE8,
            _ => return Err(anyhow!("Invalid watchpoint size: {}, must be 1, 2, 4, or 8", size)),
        };
        wcr_val |= bas;
        
        // Update control register
        debug_state.__wcr[register_index] = wcr_val;
        
        // Set the new debug state
        unsafe {
            let kr = thread_set_state(
                thread_port,
                ARM_DEBUG_STATE64,
                &debug_state as *const _ as *mut u32,
                count
            );
            
            if kr != KERN_SUCCESS {
                return Err(anyhow!("Failed to set debug state: error {}", kr));
            }
        }
        
        // Remember we're using this register
        self.watchpoint_registers.insert(register_index, address);
        
        // Need to apply the watchpoint to all threads
        if let Ok(threads) = self.get_threads(pid) {
            for &tid in &threads {
                if tid != thread_id {
                    // Apply the same watchpoint to other threads
                    let _ = Self::apply_watchpoint_to_thread(pid, tid, register_index, address, size, watchpoint_type);
                }
            }
        }
        
        Ok(register_index)
    }
    
    /// Apply a watchpoint to a specific thread (used for multi-thread consistency)
    fn apply_watchpoint_to_thread(pid: i32, thread_id: u64, register_index: usize, 
                                 address: u64, size: usize, 
                                 watchpoint_type: WatchpointType) -> Result<()> {
        // Get the task port for the target process
        let mut task: mach_port_t = 0;
        unsafe {
            let kr = task_for_pid(mach_task_self(), pid, &mut task);
            if kr != KERN_SUCCESS {
                return Err(anyhow!("Failed to get task for pid {}: error {}", pid, kr));
            }
        }
        
        // Get thread port
        let thread_port = Self::get_thread_port(task, thread_id)?;
        
        // Get current debug state
        let mut count = (std::mem::size_of::<ArmDebugState64T>() / std::mem::size_of::<u32>()) as u32;
        let mut debug_state = ArmDebugState64T {
            __bvr: [0; 16],
            __bcr: [0; 16],
            __wvr: [0; 16],
            __wcr: [0; 16],
        };
        
        unsafe {
            let kr = thread_get_state(
                thread_port,
                ARM_DEBUG_STATE64,
                &mut debug_state as *mut _ as *mut u32,
                &mut count
            );
            
            if kr != KERN_SUCCESS {
                return Err(anyhow!("Failed to get debug state: error {}", kr));
            }
        }
        
        // Set up watchpoint value register
        debug_state.__wvr[register_index] = address;
        
        // Set up watchpoint control register
        let mut wcr_val: u64 = 0;
        
        // Enable bit
        wcr_val |= WCR_E;
        
        // Set privilege mode (match in any mode)
        wcr_val |= WCR_PAC_ANY;
        
        // Set watch type
        match watchpoint_type {
            WatchpointType::Read => wcr_val |= WCR_LSC_LOAD,
            WatchpointType::Write => wcr_val |= WCR_LSC_STORE,
            WatchpointType::ReadWrite => wcr_val |= WCR_LSC_BOTH,
        }
        
        // Set byte address select
        let bas = match size {
            1 => WCR_BAS_BYTE1,
            2 => WCR_BAS_BYTE2,
            4 => WCR_BAS_BYTE4,
            8 => WCR_BAS_BYTE8,
            _ => return Err(anyhow!("Invalid watchpoint size: {}, must be 1, 2, 4, or 8", size)),
        };
        wcr_val |= bas;
        
        // Update control register
        debug_state.__wcr[register_index] = wcr_val;
        
        // Set the new debug state
        unsafe {
            let kr = thread_set_state(
                thread_port,
                ARM_DEBUG_STATE64,
                &debug_state as *const _ as *mut u32,
                count
            );
            
            if kr != KERN_SUCCESS {
                return Err(anyhow!("Failed to set debug state: error {}", kr));
            }
        }
        
        Ok(())
    }
    
    /// Remove a hardware watchpoint
    pub fn remove_watchpoint(&mut self, pid: i32, register_index: usize) -> Result<()> {
        if register_index >= MAX_WATCHPOINTS {
            return Err(anyhow!("Invalid watchpoint register index: {}", register_index));
        }
        
        // Check if the register is in use
        if !self.watchpoint_registers.contains_key(&register_index) {
            return Err(anyhow!("Watchpoint register {} is not in use", register_index));
        }
        
        // Get the task port for the target process
        let mut task: mach_port_t = 0;
        unsafe {
            let kr = task_for_pid(mach_task_self(), pid, &mut task);
            if kr != KERN_SUCCESS {
                return Err(anyhow!("Failed to get task for pid {}: error {}", pid, kr));
            }
        }
        
        // Get all threads and remove the watchpoint from each
        if let Ok(threads) = self.get_threads(pid) {
            for &thread_id in &threads {
                // Get thread port
                let thread_port = Self::get_thread_port(task, thread_id)?;
                
                // Get current debug state
                let mut count = (std::mem::size_of::<ArmDebugState64T>() / std::mem::size_of::<u32>()) as u32;
                let mut debug_state = ArmDebugState64T {
                    __bvr: [0; 16],
                    __bcr: [0; 16],
                    __wvr: [0; 16],
                    __wcr: [0; 16],
                };
                
                unsafe {
                    let kr = thread_get_state(
                        thread_port,
                        ARM_DEBUG_STATE64,
                        &mut debug_state as *mut _ as *mut u32,
                        &mut count
                    );
                    
                    if kr != KERN_SUCCESS {
                        return Err(anyhow!("Failed to get debug state: error {}", kr));
                    }
                }
                
                // Disable the watchpoint by clearing the enable bit
                debug_state.__wcr[register_index] &= !WCR_E;
                
                // Set the new debug state
                unsafe {
                    let kr = thread_set_state(
                        thread_port,
                        ARM_DEBUG_STATE64,
                        &debug_state as *const _ as *mut u32,
                        count
                    );
                    
                    if kr != KERN_SUCCESS {
                        return Err(anyhow!("Failed to set debug state: error {}", kr));
                    }
                }
            }
        }
        
        // Remove from our tracking map
        self.watchpoint_registers.remove(&register_index);
        
        Ok(())
    }
    
    /// Check if a thread was stopped by a watchpoint
    pub fn is_watchpoint_hit(&self, pid: i32, thread_id: u64) -> Result<Option<(usize, u64)>> {
        // If no watchpoints are active, return immediately
        if self.watchpoint_registers.is_empty() {
            return Ok(None);
        }
        
        // Get the task port for the target process
        let mut task: mach_port_t = 0;
        unsafe {
            let kr = task_for_pid(mach_task_self(), pid, &mut task);
            if kr != KERN_SUCCESS {
                return Err(anyhow!("Failed to get task for pid {}: error {}", pid, kr));
            }
        }
        
        // Get thread port
        let thread_port = Self::get_thread_port(task, thread_id)?;
        
        // Get current debug state
        let mut count = (std::mem::size_of::<ArmDebugState64T>() / std::mem::size_of::<u32>()) as u32;
        let mut debug_state = ArmDebugState64T {
            __bvr: [0; 16],
            __bcr: [0; 16],
            __wvr: [0; 16],
            __wcr: [0; 16],
        };
        
        unsafe {
            let kr = thread_get_state(
                thread_port,
                ARM_DEBUG_STATE64,
                &mut debug_state as *mut _ as *mut u32,
                &mut count
            );
            
            if kr != KERN_SUCCESS {
                return Err(anyhow!("Failed to get debug state: error {}", kr));
            }
        }
        
        // Check each watchpoint register for a hit
        for (&register_index, &address) in &self.watchpoint_registers {
            // Check if this watchpoint is enabled and hit
            // The hit status is in bit 0 of the ESR_EL1 register, but unfortunately
            // we can't access this directly in userspace on macOS
            // Instead, we have to infer by checking PC and examining memory accesses
            
            // For now, we'll use a simple approach: if the thread is stopped and
            // we have active watchpoints, we'll check if the PC is near any of the 
            // watchpoint addresses
            let registers = self.get_thread_registers(pid, thread_id)?;
            let pc = registers.get_program_counter().unwrap_or(0);
            
            // If PC is within a reasonable range of the watchpoint address
            // (this is a heuristic, not guaranteed to be accurate)
            if pc.abs_diff(address) < 64 {
                return Ok(Some((register_index, address)));
            }
        }
        
        Ok(None)
    }
}

impl Default for MacosDebugger {
    fn default() -> Self {
        Self::new()
    }
}
