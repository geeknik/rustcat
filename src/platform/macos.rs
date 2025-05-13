use std::process::{Command, Child};
use std::ptr;
use std::collections::HashMap;
use std::time::Instant;

use anyhow::{anyhow, Result};
use log::{info, debug, warn, error};

// Mach types and constants
use mach2::mach_types::{task_t, thread_act_t};
use mach2::kern_return::KERN_SUCCESS;
use mach2::vm_types::{mach_vm_address_t, mach_vm_size_t};
use mach2::port::{mach_port_t, MACH_PORT_NULL};
use mach2::message::mach_msg_type_number_t;
use mach2::task::{task_resume, task_suspend, task_threads};
use mach2::traps::{task_for_pid, mach_task_self};
use mach2::thread_act::{thread_suspend, thread_get_state, thread_set_state};
use mach2::vm::{mach_vm_read_overwrite, mach_vm_write, mach_vm_protect, mach_vm_deallocate, mach_vm_region};
use mach2::vm_region::VM_REGION_BASIC_INFO_64;
use mach2::vm_region::vm_region_basic_info_data_64_t;

// Libc for waitpid, ptrace
use libc::{pid_t, waitpid, WIFSTOPPED, WSTOPSIG};
use libc::{PT_ATTACHEXC, PT_DETACH, PT_CONTINUE};
use libc::pthread_getname_np;

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
const MAX_WATCHPOINTS: usize = 8;       // M1/M2 typically have 8 watchpoint registers

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

// Define hardware breakpoint constants
// BCR - Breakpoint Control Register bits
const BCR_E: u64 = 0x1;                // Enable bit (bit 0)
const BCR_PMC_MASK: u64 = 0x3 << 1;    // Privilege Access Control (bits 1-2)
const BCR_PMC_ANY: u64 = 0x3 << 1;     // Match in any mode
const BCR_BAS_MASK: u64 = 0xFF << 5;   // Byte Address Select (bits 5-12)
const BCR_BAS_THUMB: u64 = 0x03 << 5;  // Match thumb instruction (2 bytes)
const BCR_BAS_ARM: u64 = 0x0F << 5;    // Match ARM instruction (4 bytes)
const BCR_MASK: u64 = 0x0000_FFFF;     // Mask for the control bits we use

// Maximum number of hardware breakpoints on Apple Silicon
const MAX_BREAKPOINTS: usize = 8;      // M1/M2 typically have 8 hardware breakpoint registers

/// MacOS-specific debugger implementation
pub struct MacosDebugger {
    /// The task port for the target process
    task_port: Option<task_t>,
    /// The child process handle (if launched by us)
    child: Option<Child>,
    /// Thread list cache
    threads: Vec<thread_act_t>,
    /// Currently active hardware watchpoints (`register_index` -> address)
    watchpoint_registers: HashMap<usize, u64>,
}

impl MacosDebugger {
    /// Create a new macOS debugger instance
    pub fn new() -> Self {
        Self {
            task_port: None,
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
            let wait_result = waitpid(pid, &raw mut status, 0);
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
                &raw mut task_port,
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
        
        // Remove all breakpoints and watchpoints
        // For hardware breakpoints and watchpoints, iterate through all active threads
        if let Ok(threads) = self.get_threads(pid) {
            // For each thread, clear all hardware breakpoints
            for thread_id in threads {
                // Disable all hardware breakpoints
                for i in 0..MAX_BREAKPOINTS {
                    let _ = Self::disable_hardware_breakpoint_on_thread(pid, thread_id, i);
                }
                
                // Disable all hardware watchpoints
                for i in 0..MAX_WATCHPOINTS {
                    let _ = Self::disable_hardware_watchpoint_on_thread(pid, thread_id, i);
                }
            }
        }
        
        // Clear all software breakpoints (if we had tracked them in a map)
        // In a real implementation, we would have a map of addresses to original bytes
        // and restore all of those here
        
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
        self.watchpoint_registers.clear();
        
        debug!("Successfully detached from process {}", pid);
        Ok(())
    }
    
    /// Continue execution of a process
    /// 
    /// # Panics
    ///
    /// Panics if not attached to any process when unwrapping the task port
    pub fn continue_execution(&mut self, pid: i32) -> Result<()> {
        if self.task_port.is_none() {
            return Err(anyhow!("Not attached to any process"));
        }
        
        info!("Continuing execution of process {}", pid);
        
        // Use ptrace to continue execution from current position
        // The (caddr_t)1 means continue from current position
        unsafe {
            let result = libc::ptrace(PT_CONTINUE as _, pid, std::ptr::dangling_mut::<libc::c_char>(), 0);
            if result < 0 {
                return Err(anyhow!("Failed to continue process {}: {}", pid, std::io::Error::last_os_error()));
            }
        }
        
        // Additionally, ensure all threads are resumed at the Mach level
        let task_port = self.task_port.unwrap();
        let kr = unsafe { task_resume(task_port) };
        if kr == KERN_SUCCESS {
            debug!("Successfully resumed task at Mach level");
        } else {
            warn!("Failed to resume task at Mach level: {}", kr);
            // Continue anyway, as ptrace should have worked
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
        let mut arm_thread_state: ArmThreadState64T = unsafe { std::mem::zeroed() };
        let mut count = ARM_THREAD_STATE64_COUNT;
        
        let kr = unsafe {
            thread_get_state(
                thread,
                ARM_THREAD_STATE64,
                (&raw mut arm_thread_state).cast::<u32>(),
                &raw mut count
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
        let mut arm_thread_state: ArmThreadState64T = unsafe { std::mem::zeroed() };
        
        // First, get current state as baseline
        let mut count = ARM_THREAD_STATE64_COUNT;
        let kr = unsafe {
            thread_get_state(
                thread,
                ARM_THREAD_STATE64,
                (&raw mut arm_thread_state).cast::<u32>(),
                &raw mut count
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
                &raw const arm_thread_state as *mut u32,
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
    
    /// Helper function to read memory using `mach_vm_read_overwrite`
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
                    &raw mut bytes_read
                )
            };
            
            // Check return status and bytes read
            if kr != KERN_SUCCESS {
                error!("Failed to read memory at 0x{:x}: Error {}", address, kr);
                return Err(anyhow!("Failed to read memory at 0x{:x}: Error {}", address, kr));
            }
            
            // Check if we read the expected number of bytes
            if bytes_read as usize == buffer.len() {
                debug!("Successfully read {} bytes from address 0x{:x}", bytes_read, address);
            } else {
                warn!("Partial memory read at 0x{:x}: expected {} bytes, got {}", 
                    address, buffer.len(), bytes_read);
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
    
    /// Helper function to write memory using `mach_vm_write`
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
        
        // In macOS, we need to:
        // 1. Get current thread state
        // 2. Set the single-step bit in CPSR
        // 3. Continue execution (with thread-specific controls if needed)
        // 4. Wait for the SIGTRAP that indicates the step is complete
        
        // First, get current registers
        let mut registers = self.get_registers(pid)?;
        
        // Set the single-step bit in CPSR (T bit for ARM)
        // For ARM64, bit 21 of PSTATE/CPSR is the SS (Single Step) bit
        if let Some(cpsr) = registers.get(Register::Cpsr) {
            // Set SS bit (bit 21)
            let new_cpsr = cpsr | (1 << 21);
            registers.set(Register::Cpsr, new_cpsr);
            
            // Update registers with the modified CPSR
            self.set_registers(pid, &registers)?;
        } else {
            return Err(anyhow!("Failed to get CPSR register for thread 0x{:x}", thread));
        }
        
        // Continue execution
        unsafe {
            let result = libc::ptrace(PT_CONTINUE as _, pid, std::ptr::null_mut(), 0);
            if result < 0 {
                return Err(anyhow!("Failed to continue process after setting single-step: {}", 
                    std::io::Error::last_os_error()));
            }
        }
        
        // Wait for the process to stop with SIGTRAP
        let mut status = 0;
        unsafe {
            let wait_result = waitpid(pid, &raw mut status, 0);
            if wait_result < 0 {
                return Err(anyhow!("Failed to wait for process {}: {}", 
                    pid, std::io::Error::last_os_error()));
            }
            
            if !WIFSTOPPED(status) {
                return Err(anyhow!("Process {} did not stop after single-step", pid));
            }
            
            let stop_signal = WSTOPSIG(status);
            debug!("Process {} stopped with signal {} after single-step", pid, stop_signal);
        }
        
        // Clear the single-step bit from CPSR
        if let Some(cpsr) = registers.get(Register::Cpsr) {
            // Clear SS bit (bit 21)
            let new_cpsr = cpsr & !(1 << 21);
            registers.set(Register::Cpsr, new_cpsr);
            
            // Update registers with the modified CPSR
            self.set_registers(pid, &registers)?;
        }
        
        debug!("Successfully stepped thread 0x{:x}", thread);
        
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
                    &raw mut thread_list,
                    &raw mut thread_count
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
    pub fn get_memory_protection(&self, address: u64) -> Result<u32> {
        if let Some(task_port) = self.task_port {
            debug!("Getting memory protection for address 0x{:x}", address);
            
            // Variables for mach_vm_region call
            let mut address_as_vm_address = address as mach_vm_address_t;
            let mut size: mach_vm_size_t = 0;
            let mut object_name: mach_port_t = 0;
            
            // Region info structure
            let mut info: vm_region_basic_info_data_64_t = unsafe { std::mem::zeroed() };
            let mut count = std::mem::size_of::<vm_region_basic_info_data_64_t>() as mach_msg_type_number_t / std::mem::size_of::<i32>() as mach_msg_type_number_t;
            
            // Call mach_vm_region to get region information
            let kr = unsafe {
                mach_vm_region(
                    task_port,
                    &mut address_as_vm_address,
                    &mut size,
                    VM_REGION_BASIC_INFO_64,
                    (&mut info as *mut vm_region_basic_info_data_64_t).cast::<i32>(),
                    &mut count,
                    &mut object_name
                )
            };
            
            if kr != KERN_SUCCESS {
                error!("Failed to get memory region info for address 0x{:x}: Error {}", address, kr);
                return Err(anyhow!("Failed to get memory region info for address 0x{:x}: Error {}", address, kr));
            }
            
            // Extract protection flags
            let current_protection = info.protection as u32;
            
            debug!("Address 0x{:x} has protection 0x{:x}", address, current_protection);
            
            // Return the current protection flags
            Ok(current_protection)
        } else {
            Err(anyhow!("Not attached to any process"))
        }
    }
    
    /// Set memory protection flags for a region
    #[allow(dead_code)]
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
        
        // For macOS, we'll use waitpid with WNOHANG to poll and implement our own timeout
        let start_time = std::time::Instant::now();
        let timeout = std::time::Duration::from_millis(timeout_ms);
        
        let mut status = 0;
        
        loop {
            // Check if we've exceeded the timeout
            if start_time.elapsed() > timeout {
                return Err(anyhow!("Timeout waiting for process {} to stop", pid));
            }
            
            // Try waitpid with WNOHANG (return immediately)
            let wait_result = unsafe { waitpid(pid, &raw mut status, libc::WNOHANG) };
            
            if wait_result < 0 {
                // Error occurred
                return Err(anyhow!("Failed to wait for process {}: {}", 
                    pid, std::io::Error::last_os_error()));
            } else if wait_result == 0 {
                // Process is still running, wait a bit and try again
                std::thread::sleep(std::time::Duration::from_millis(10));
                continue;
            } else {
                // Process status changed
                if WIFSTOPPED(status) {
                    // Process stopped with a signal
                    let stop_signal = WSTOPSIG(status);
                    debug!("Process {} stopped with signal {}", pid, stop_signal);
                    return Ok(());
                } else {
                    // Process exited or other status change
                    return Err(anyhow!("Process {} changed state but did not stop (status={})", 
                        pid, status));
                }
            }
        }
    }
    
    /// Query hardware debug capabilities
    pub fn get_debug_capabilities(&self) -> DebugCapabilities {
        // On Apple Silicon, we typically have 8 hardware breakpoint registers
        // and 4 hardware watchpoint registers
        DebugCapabilities {
            hw_breakpoint_count: MAX_BREAKPOINTS,
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
                &raw mut thread_list,
                &raw mut thread_count
            );
            
            if kr != KERN_SUCCESS {
                return Err(anyhow!("Failed to get threads for task: error {}", kr));
            }
            
            // Look for a matching thread port in the list
            let mut found = false;
            for i in 0..thread_count {
                let current_thread = *thread_list.cast_const().add(i as usize);
                if u64::from(current_thread) == thread_id {
                    found = true;
                    break;
                }
            }
            
            // Deallocate the thread list when done
            let _ = mach_vm_deallocate(
                mach_task_self(),
                thread_list as mach_vm_address_t,
                mach_vm_size_t::from(thread_count * std::mem::size_of::<mach_port_t>() as u32)
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
                (&raw mut state).cast::<u32>(),
                &raw mut count
            );
            
            if kr != KERN_SUCCESS {
                return Err(anyhow!("Invalid thread port {}: error {}", thread_id, kr));
            }
        }
        
        Ok(thread_id as thread_act_t)
    }
    
    /// Get list of threads for a process
    pub fn get_threads(&self, pid: i32) -> Result<Vec<u64>> {
        if let Some(task_port) = self.task_port {
            // Get thread list from task
            let mut thread_list = std::ptr::null_mut();
            let mut thread_count: mach_msg_type_number_t = 0;
            
            unsafe {
                let kr = task_threads(
                    task_port,
                    &raw mut thread_list,
                    &raw mut thread_count
                );
                
                if kr != KERN_SUCCESS {
                    return Err(anyhow!("Failed to get threads for process {}: error {}", pid, kr));
                }
                
                // Convert thread ports to thread IDs (use the port value as ID for now)
                let mut thread_ids = Vec::with_capacity(thread_count as usize);
                
                for i in 0..thread_count {
                    let thread_port = *thread_list.cast_const().add(i as usize);
                    thread_ids.push(u64::from(thread_port));
                    
                    // Ideally we would deallocate the thread port reference here,
                    // but we'll rely on mach_vm_deallocate below to clean up
                }
                
                // Deallocate the thread list
                let _ = mach_vm_deallocate(
                    mach_task_self(),
                    thread_list as mach_vm_address_t,
                    mach_vm_size_t::from(thread_count * std::mem::size_of::<mach_port_t>() as u32)
                );
                
                debug!("Found {} threads for process {}", thread_ids.len(), pid);
                return Ok(thread_ids);
            }
        }
        
        Err(anyhow!("Not attached to any process"))
    }
    
    /// Get registers for a thread
    pub fn get_thread_registers(&self, pid: i32, thread_id: u64) -> Result<Registers> {
        // Validate that we're connected to the correct process
        if self.task_port.is_none() {
            return Err(anyhow!("Not attached to any process"));
        }
        
        // Confirm that the process ID matches what we expect
        if let Ok(current_pid) = self.get_current_pid() {
            if current_pid != pid {
                return Err(anyhow!("PID mismatch: expected {}, got {}", pid, current_pid));
            }
        }
        
        // Get the thread port for the thread ID
        let thread_port = Self::get_thread_port(self.task_port.unwrap_or(MACH_PORT_NULL), thread_id)?;
        
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
                (&raw mut arm_thread_state).cast::<u32>(),
                &raw mut count
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
    
    /// Set a hardware breakpoint at the specified address
    pub fn set_hardware_breakpoint(&mut self, pid: i32, thread_id: u64, address: u64) -> Result<usize> {
        // Check if we have any free breakpoint registers
        let mut hardware_breakpoints = HashMap::new();
        
        // Get debug capabilities to verify hardware breakpoint count
        let capabilities = self.get_debug_capabilities();
        if capabilities.hw_breakpoint_count == 0 {
            return Err(anyhow!("Hardware breakpoints are not supported on this platform"));
        }
        
        // Find the next available register index by checking debug state
        // Get the task port for the target process
        let mut task: mach_port_t = 0;
        unsafe {
            let kr = task_for_pid(mach_task_self(), pid, &raw mut task);
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
                (&raw mut debug_state).cast::<u32>(),
                &raw mut count
            );
            
            if kr != KERN_SUCCESS {
                return Err(anyhow!("Failed to get debug state: error {}", kr));
            }
        }
        
        // Check for existing enabled breakpoints and find a free slot
        for i in 0..MAX_BREAKPOINTS {
            if (debug_state.__bcr[i] & BCR_E) != 0 {
                // This breakpoint is enabled, remember its address
                hardware_breakpoints.insert(i, debug_state.__bvr[i]);
            }
        }
        
        // Find a free register
        let free_count = MAX_BREAKPOINTS - hardware_breakpoints.len();
        if free_count == 0 {
            return Err(anyhow!("No free hardware breakpoint registers available"));
        }
        
        let register_index = (0..MAX_BREAKPOINTS)
            .find(|i| !hardware_breakpoints.contains_key(i))
            .unwrap(); // Safe because we checked free_count > 0
        
        // Set breakpoint value register (BVR) to target address
        debug_state.__bvr[register_index] = address;
        
        // Configure breakpoint control register (BCR)
        let mut bcr_val: u64 = 0;
        
        // Enable bit
        bcr_val |= BCR_E;
        
        // Set privilege mode (match in any mode)
        bcr_val |= BCR_PMC_ANY;
        
        // Set byte address select based on instruction type
        // For ARM64, we use BCR_BAS_ARM (match all 4 bytes)
        bcr_val |= BCR_BAS_ARM;
        
        // Update control register
        debug_state.__bcr[register_index] = bcr_val;
        
        // Set the new debug state
        unsafe {
            let kr = thread_set_state(
                thread_port,
                ARM_DEBUG_STATE64,
                &raw const debug_state as *mut u32,
                count
            );
            
            if kr != KERN_SUCCESS {
                return Err(anyhow!("Failed to set debug state: error {}", kr));
            }
        }
        
        // Apply the same breakpoint to all threads for consistency
        if let Ok(threads) = self.get_threads(pid) {
            for &tid in &threads {
                if tid != thread_id {
                    // Apply the same breakpoint to other threads
                    let _ = Self::apply_hardware_breakpoint_to_thread(pid, tid, register_index, address);
                }
            }
        }
        
        Ok(register_index)
    }
    
    /// Apply a hardware breakpoint to a specific thread (used for multi-thread consistency)
    fn apply_hardware_breakpoint_to_thread(pid: i32, thread_id: u64, register_index: usize, address: u64) -> Result<()> {
        // Get the task port for the target process
        let mut task: mach_port_t = 0;
        unsafe {
            let kr = task_for_pid(mach_task_self(), pid, &raw mut task);
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
                (&raw mut debug_state).cast::<u32>(),
                &raw mut count
            );
            
            if kr != KERN_SUCCESS {
                return Err(anyhow!("Failed to get debug state: error {}", kr));
            }
        }
        
        // Set breakpoint value register (BVR) to target address
        debug_state.__bvr[register_index] = address;
        
        // Configure breakpoint control register (BCR)
        let mut bcr_val: u64 = 0;
        
        // Enable bit
        bcr_val |= BCR_E;
        
        // Set privilege mode (match in any mode)
        bcr_val |= BCR_PMC_ANY;
        
        // Set byte address select based on instruction type
        // For ARM64, we use BCR_BAS_ARM (match all 4 bytes)
        bcr_val |= BCR_BAS_ARM;
        
        // Update control register
        debug_state.__bcr[register_index] = bcr_val;
        
        // Set the new debug state
        unsafe {
            let kr = thread_set_state(
                thread_port,
                ARM_DEBUG_STATE64,
                &raw const debug_state as *mut u32,
                count
            );
            
            if kr != KERN_SUCCESS {
                return Err(anyhow!("Failed to set debug state: error {}", kr));
            }
        }
        
        Ok(())
    }
    
    /// Remove a hardware breakpoint
    pub fn remove_hardware_breakpoint(&mut self, pid: i32, thread_id: u64, register_index: usize) -> Result<()> {
        if register_index >= MAX_BREAKPOINTS {
            return Err(anyhow!("Invalid hardware breakpoint register index: {}", register_index));
        }
        
        // Get the task port for the target process
        let mut task: mach_port_t = 0;
        unsafe {
            let kr = task_for_pid(mach_task_self(), pid, &raw mut task);
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
                (&raw mut debug_state).cast::<u32>(),
                &raw mut count
            );
            
            if kr != KERN_SUCCESS {
                return Err(anyhow!("Failed to get debug state: error {}", kr));
            }
        }
        
        // Disable the breakpoint by clearing the enable bit
        debug_state.__bcr[register_index] &= !BCR_E;
        
        // Set the new debug state
        unsafe {
            let kr = thread_set_state(
                thread_port,
                ARM_DEBUG_STATE64,
                &raw const debug_state as *mut u32,
                count
            );
            
            if kr != KERN_SUCCESS {
                return Err(anyhow!("Failed to set debug state: error {}", kr));
            }
        }
        
        // Apply to all threads for consistency
        if let Ok(threads) = self.get_threads(pid) {
            for &tid in &threads {
                if tid != thread_id {
                    // Apply the same change to other threads
                    let _ = Self::disable_hardware_breakpoint_on_thread(pid, tid, register_index);
                }
            }
        }
        
        Ok(())
    }
    
    /// Disable a hardware breakpoint on a specific thread
    fn disable_hardware_breakpoint_on_thread(pid: i32, thread_id: u64, register_index: usize) -> Result<()> {
        // Get the task port for the target process
        let mut task: mach_port_t = 0;
        unsafe {
            let kr = task_for_pid(mach_task_self(), pid, &raw mut task);
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
                (&raw mut debug_state).cast::<u32>(),
                &raw mut count
            );
            
            if kr != KERN_SUCCESS {
                return Err(anyhow!("Failed to get debug state: error {}", kr));
            }
        }
        
        // Disable the breakpoint by clearing the enable bit
        debug_state.__bcr[register_index] &= !BCR_E;
        
        // Set the new debug state
        unsafe {
            let kr = thread_set_state(
                thread_port,
                ARM_DEBUG_STATE64,
                &raw const debug_state as *mut u32,
                count
            );
            
            if kr != KERN_SUCCESS {
                return Err(anyhow!("Failed to set debug state: error {}", kr));
            }
        }
        
        Ok(())
    }
    
    /// Check if a hardware breakpoint has been hit
    pub fn is_hardware_breakpoint_hit(&self, pid: i32, thread_id: u64) -> Result<Option<(usize, u64)>> {
        // Get the task port for the target process
        let mut task: mach_port_t = 0;
        unsafe {
            let kr = task_for_pid(mach_task_self(), pid, &raw mut task);
            if kr != KERN_SUCCESS {
                return Err(anyhow!("Failed to get task for pid {}: error {}", pid, kr));
            }
        }
        
        // Get thread port
        let thread_port = Self::get_thread_port(task, thread_id)?;
        
        // Get current debug state
        let mut debug_state = ArmDebugState64T {
            __bvr: [0; 16],
            __bcr: [0; 16],
            __wvr: [0; 16],
            __wcr: [0; 16],
        };
        
        let mut count = (std::mem::size_of::<ArmDebugState64T>() / std::mem::size_of::<u32>()) as mach_msg_type_number_t;
        
        unsafe {
            let kr = thread_get_state(
                thread_port,
                ARM_DEBUG_STATE64,
                std::mem::transmute(&mut debug_state),
                &mut count
            );
            
            if kr != KERN_SUCCESS {
                return Err(anyhow!("Failed to get thread debug state: {}", kr));
            }
        }
        
        // On ARM64, we need to check if ESR_EL1 indicates a debug exception
        // We'll infer this from the fact that the instruction pointer is at
        // a location that matches one of our breakpoints
        
        // Get the program counter
        let registers = self.get_thread_registers(pid, thread_id)?;
        let pc = registers.get(Register::Pc).unwrap_or(0);
        
        // Check if PC matches any of our BVR registers
        for i in 0..MAX_BREAKPOINTS {
            if (debug_state.__bcr[i] & BCR_E) != 0 {
                // This breakpoint is enabled
                let bp_addr = debug_state.__bvr[i];
                if pc == bp_addr {
                    // Hardware breakpoint hit!
                    return Ok(Some((i, bp_addr)));
                }
            }
        }
        
        // No hardware breakpoint hit
        Ok(None)
    }
    
    /// Set a hardware watchpoint
    pub fn set_watchpoint(&mut self, pid: i32, thread_id: u64, address: u64, size: usize, watchpoint_type: WatchpointType) -> Result<usize> {
        // Check if we have a free watchpoint register
        let register_index = self.watchpoint_registers.iter()
            .find(|(_, &addr)| addr == address)
            .map(|(&idx, _)| idx)
            .unwrap_or_else(|| {
                // Find first free register
                (0..MAX_WATCHPOINTS).find(|&i| !self.watchpoint_registers.contains_key(&i))
                    .unwrap_or(0)
            });
        
        if register_index >= MAX_WATCHPOINTS {
            return Err(anyhow!("No free hardware watchpoint registers available"));
        }
        
        // Get thread port
        let result = Self::set_hardware_watchpoint_on_thread(
            pid, 
            thread_id, 
            register_index, 
            address, 
            size, 
            watchpoint_type
        );
        
        if result.is_ok() {
            // Store in our register map
            self.watchpoint_registers.insert(register_index, address);
            
            // Apply to all threads for consistency
            if let Ok(threads) = self.get_threads(pid) {
                for &tid in &threads {
                    if tid != thread_id {
                        // Apply the same watchpoint to other threads
                        let _ = Self::set_hardware_watchpoint_on_thread(
                            pid, 
                            tid, 
                            register_index, 
                            address, 
                            size, 
                            watchpoint_type
                        );
                    }
                }
            }
        }
        
        Ok(register_index)
    }
    
    /// Set a hardware watchpoint on a specific thread
    fn set_hardware_watchpoint_on_thread(
        pid: i32, 
        thread_id: u64, 
        register_index: usize, 
        address: u64,
        size: usize,
        watchpoint_type: WatchpointType
    ) -> Result<()> {
        if register_index >= MAX_WATCHPOINTS {
            return Err(anyhow!("Invalid hardware watchpoint register index: {}", register_index));
        }
        
        // Get the task port for the target process
        let mut task: mach_port_t = 0;
        unsafe {
            let kr = task_for_pid(mach_task_self(), pid, &raw mut task);
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
                (&raw mut debug_state).cast::<u32>(),
                &raw mut count
            );
            
            if kr != KERN_SUCCESS {
                return Err(anyhow!("Failed to get debug state: error {}", kr));
            }
        }
        
        // Set watchpoint address
        debug_state.__wvr[register_index] = address;
        
        // Set watchpoint control register
        // WCR bits:
        // E (bit 0): Enable
        // PAC (bits 1-2): Privileged access control
        // LSC (bits 3-4): Load/store control
        //   00: Reserved
        //   01: Load
        //   10: Store
        //   11: Load or store
        // BAS (bits 5-12): Byte address select
        // HMC (bit 13): Higher mode control
        // SSC (bits 14-15): Security state control
        // LBN (bits 16-19): Linked BRP number
        // WT (bit 20): Watchpoint type
        
        // Set size mask (BAS field)
        let bas = match size {
            1 => 0x01, // 1 byte
            2 => 0x03, // 2 bytes
            4 => 0x0F, // 4 bytes
            8 => 0xFF, // 8 bytes
            _ => return Err(anyhow!("Unsupported watchpoint size: {}", size)),
        };
        
        // Set load/store control bits (LSC field)
        let lsc = match watchpoint_type {
            WatchpointType::Read => 0x01, // Load only
            WatchpointType::Write => 0x02, // Store only
            WatchpointType::ReadWrite => 0x03, // Load or store
            WatchpointType::Conditional => 0x03, // Use Read/Write for conditional
            WatchpointType::Logging => 0x03, // Use Read/Write for logging
        };
        
        // Set watchpoint control
        debug_state.__wcr[register_index] = 
            1 |                          // E (enabled)
            (3 << 1) |                   // PAC: Allow all privilege levels
            (lsc << 3) |                 // LSC: Load/store control
            ((bas as u64) << 5) |        // BAS: Byte address select
            (3 << 14);                   // SSC: All security states
        
        // Set the new debug state
        unsafe {
            let kr = thread_set_state(
                thread_port,
                ARM_DEBUG_STATE64,
                &raw const debug_state as *mut u32,
                count
            );
            
            if kr != KERN_SUCCESS {
                return Err(anyhow!("Failed to set debug state: error {}", kr));
            }
        }
        
        Ok(())
    }
    
    /// Remove a hardware watchpoint
    pub fn remove_hardware_watchpoint(&mut self, pid: i32, thread_id: u64, register_index: usize) -> Result<()> {
        if register_index >= MAX_WATCHPOINTS {
            return Err(anyhow!("Invalid hardware watchpoint register index: {}", register_index));
        }
        
        // Get the task port for the target process
        let mut task: mach_port_t = 0;
        unsafe {
            let kr = task_for_pid(mach_task_self(), pid, &raw mut task);
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
                (&raw mut debug_state).cast::<u32>(),
                &raw mut count
            );
            
            if kr != KERN_SUCCESS {
                return Err(anyhow!("Failed to get debug state: error {}", kr));
            }
        }
        
        // Disable the watchpoint by clearing the enable bit
        debug_state.__wcr[register_index] &= !1; // Clear bit 0 (E)
        
        // Set the new debug state
        unsafe {
            let kr = thread_set_state(
                thread_port,
                ARM_DEBUG_STATE64,
                &raw const debug_state as *mut u32,
                count
            );
            
            if kr != KERN_SUCCESS {
                return Err(anyhow!("Failed to set debug state: error {}", kr));
            }
        }
        
        // Remove from our register map
        self.watchpoint_registers.remove(&register_index);
        
        // Apply to all threads for consistency
        if let Ok(threads) = self.get_threads(pid) {
            for &tid in &threads {
                if tid != thread_id {
                    // Apply the same change to other threads
                    let _ = Self::disable_hardware_watchpoint_on_thread(pid, tid, register_index);
                }
            }
        }
        
        Ok(())
    }
    
    /// Disable a hardware watchpoint on a specific thread
    fn disable_hardware_watchpoint_on_thread(pid: i32, thread_id: u64, register_index: usize) -> Result<()> {
        // Get the task port for the target process
        let mut task: mach_port_t = 0;
        unsafe {
            let kr = task_for_pid(mach_task_self(), pid, &raw mut task);
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
                (&raw mut debug_state).cast::<u32>(),
                &raw mut count
            );
            
            if kr != KERN_SUCCESS {
                return Err(anyhow!("Failed to get debug state: error {}", kr));
            }
        }
        
        // Disable the watchpoint by clearing the enable bit
        debug_state.__wcr[register_index] &= !1; // Clear bit 0 (E)
        
        // Set the new debug state
        unsafe {
            let kr = thread_set_state(
                thread_port,
                ARM_DEBUG_STATE64,
                &raw const debug_state as *mut u32,
                count
            );
            
            if kr != KERN_SUCCESS {
                return Err(anyhow!("Failed to set debug state: error {}", kr));
            }
        }
        
        Ok(())
    }
    
    /// Check if a hardware watchpoint has been hit by examining debug registers
    /// Returns (register_index, address) if a watchpoint was hit
    pub fn is_hardware_watchpoint_hit(&self, _pid: i32, thread_id: u64) -> Result<Option<(usize, u64)>> {
        // Get the thread port
        let thread_port = Self::get_thread_port(self.task_port.unwrap_or(0), thread_id)?;
        
        // Get the debug state
        let mut debug_state = ArmDebugState64T {
            __bvr: [0; 16],
            __bcr: [0; 16],
            __wvr: [0; 16],
            __wcr: [0; 16],
        };
        
        let mut count = (std::mem::size_of::<ArmDebugState64T>() / std::mem::size_of::<u32>()) as mach_msg_type_number_t;
        
        unsafe {
            let kr = thread_get_state(
                thread_port,
                ARM_DEBUG_STATE64,
                std::mem::transmute(&mut debug_state),
                &mut count
            );
            
            if kr != KERN_SUCCESS {
                return Err(anyhow!("Failed to get thread debug state: {}", kr));
            }
        }
        
        // Go through each watchpoint register and see if any are enabled and showing a hit
        for i in 0..MAX_WATCHPOINTS {
            let wcr = debug_state.__wcr[i];
            
            // Check if this watchpoint is enabled and triggered
            if (wcr & WCR_E) != 0 {
                // On ARM, if a watchpoint is hit, hardware sets bits in PSTATE
                // We need to check thread state for those bits
                
                // For now, just check our internal hashmap of active watchpoints
                if let Some(addr) = self.watchpoint_registers.get(&i) {
                    // In a real implementation, we would check if the watchpoint was actually hit
                    // by examining the program counter and the instruction that caused the hit
                    
                    // Return the hit watchpoint
                    return Ok(Some((i, *addr)));
                }
            }
        }
        
        // No hit watchpoint found
        Ok(None)
    }

    /// Get the current process ID
    pub fn get_current_pid(&self) -> Result<i32> {
        // If we have a child process, return its PID
        if let Some(child) = &self.child {
            return Ok(child.id() as i32);
        }
        
        // If we don't have a child, we need to find another way to get the PID
        // Since we don't have direct access to task_pid_for_task and mach_task_self
        // doesn't provide a way to get the PID, we'll use a different approach
        
        // In a real debugger implementation, we would store the PID when attaching
        // to a process. For now, let's return an error if we don't have a child.
        Err(anyhow!("No child process found and PID not stored during attach"))
    }

    /// Get the program counter for a thread
    pub fn get_program_counter(&self, pid: i32, thread_id: u64) -> Result<u64> {
        // Get the current thread registers
        let registers = self.get_thread_registers(pid, thread_id)?;
        
        // Extract the program counter (PC) from the registers
        if let Some(pc) = registers.get(Register::Pc) {
            Ok(pc)
        } else {
            Err(anyhow!("Failed to get program counter for thread {}", thread_id))
        }
    }

    /// Gets thread name using pthread API, returning None if the thread doesn't have a name
    pub fn get_thread_name(thread: libc::pthread_t) -> Option<String> {
        let mut buf = [0u8; 64];
        unsafe {
            pthread_getname_np(thread, buf.as_mut_ptr() as *mut libc::c_char, buf.len());
        }
        let name = String::from_utf8_lossy(&buf).trim_end_matches('\0').to_string();
        if name.is_empty() {
            None
        } else {
            Some(name)
        }
    }

    /// Checks if a thread is the main thread
    pub fn is_main_thread(&self, thread_id: u64) -> bool {
        // On macOS, typically the first thread (index 0) is the main thread
        // But for more accurate results we can check specific properties:
        
        // 1. Check thread name - main threads often have "main thread" as name
        if let Some(name) = MacosDebugger::get_thread_name(thread_id as libc::pthread_t) {
            if name.to_lowercase().contains("main") {
                return true;
            }
        }
        
        // 2. As a fallback, check if it's the first thread in our list
        if let Ok(threads) = self.get_threads(self.get_current_pid().unwrap_or(-1)) {
            // Compare the first thread in our list with the given thread_id
            // Convert the thread_act_t type to u64 for comparison
            return threads.first().map(|&t| t as u64) == Some(thread_id);
        }
        
        false
    }
}

impl Default for MacosDebugger {
    fn default() -> Self {
        Self::new()
    }
}
