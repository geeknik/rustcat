use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use anyhow::{anyhow, Result};
use log::{info, warn, debug, error};

use crate::debugger::breakpoint::{Breakpoint, BreakpointManager, BreakpointType, ConditionEvaluator};
use crate::debugger::memory::{MemoryMap, MemoryFormat};
use crate::debugger::registers::{Registers, Register};
use crate::debugger::symbols::SymbolTable;
use crate::debugger::threads::{ThreadManager, ThreadState, StackFrame};
use crate::platform::macos::MacosDebugger;
use crate::platform::dwarf::DwarfParser;

/// Debugger state
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum DebuggerState {
    /// Not started
    Idle,
    /// Process is launched but not running
    Loaded,
    /// Process is running
    Running,
    /// Process is stopped at a breakpoint
    Stopped,
    /// Process has exited
    Exited,
}

/// Core debugger engine
pub struct Debugger {
    /// Path to the target program
    target_path: String,
    /// Arguments to pass to the target program
    args: Vec<String>,
    /// Process ID of the target program
    pid: Option<i32>,
    /// Current state of the debugger
    state: DebuggerState,
    /// Platform-specific debugger implementation
    platform: MacosDebugger,
    /// Breakpoint manager
    breakpoints: BreakpointManager,
    /// Memory map
    memory_map: Option<MemoryMap>,
    /// Symbol table
    symbols: Arc<Mutex<SymbolTable>>,
    /// Thread manager
    thread_manager: ThreadManager,
    /// DWARF parser for debug information
    dwarf_parser: DwarfParser<'static>,
    /// Start time of the debugging session
    start_time: Instant,
    /// Current breakpoint address (if stopped at one)
    current_breakpoint: Option<u64>,
}

impl Debugger {
    /// Create a new debugger instance
    pub fn new(target_path: &str) -> Result<Self> {
        // Check if the target file exists
        if !Path::new(target_path).exists() {
            return Err(anyhow!("Target program not found: {}", target_path));
        }
        
        let platform = MacosDebugger::new();
        let symbols = Arc::new(Mutex::new(SymbolTable::new()));
        let thread_manager = ThreadManager::new();
        
        info!("Initialized debugger for target: {}", target_path);
        
        Ok(Self {
            target_path: target_path.to_string(),
            args: Vec::new(),
            pid: None,
            state: DebuggerState::Idle,
            platform,
            breakpoints: BreakpointManager::new(),
            memory_map: None,
            symbols,
            thread_manager,
            dwarf_parser: DwarfParser::new(),
            start_time: Instant::now(),
            current_breakpoint: None,
        })
    }
    
    /// Set the arguments to pass to the target program
    pub fn set_args(&mut self, args: Vec<String>) {
        self.args = args;
    }
    
    /// Set the path to the target program
    pub fn set_path(&mut self, path: &str) {
        self.target_path = path.to_string();
    }
    
    /// Load symbols from the target program without starting it
    pub fn load_symbols(&mut self) -> Result<()> {
        info!("Loading symbols from target: {}", self.target_path);
        
        // Load symbols in the background
        let target_path = self.target_path.clone();
        let symbols = Arc::clone(&self.symbols);
        
        std::thread::spawn(move || {
            let start = Instant::now();
            let mut symbol_table = symbols.lock().unwrap();
            
            match symbol_table.load_from_file(&target_path) {
                Ok(_) => {
                    let elapsed = start.elapsed();
                    info!("Symbols loaded successfully in {:.2?}", elapsed);
                    info!("Loaded {} symbols", symbol_table.get_all_symbols().len());
                },
                Err(e) => {
                    error!("Error loading symbols: {}", e);
                }
            }
        });
        
        // Try to load DWARF debug info if available
        if let Err(e) = self.dwarf_parser.load(&self.target_path) {
            warn!("Error loading DWARF debug info: {}", e);
            warn!("Source-level debugging will be limited");
        }
        
        Ok(())
    }
    
    /// Load the target program
    pub fn load(&mut self) -> Result<()> {
        info!("Loading target program: {}", self.target_path);
        
        // Create process but don't start it yet
        let pid = self.platform.launch(&self.target_path)?;
        self.pid = Some(pid);
        self.state = DebuggerState::Loaded;
        
        // Initialize thread tracking
        self.thread_manager = ThreadManager::new();
        
        info!("Target program loaded, pid: {}", pid);
        
        Ok(())
    }
    
    /// Run the target program
    pub fn run(&mut self) -> Result<()> {
        if self.state == DebuggerState::Idle {
            self.load()?;
        }
        
        if let Some(pid) = self.pid {
            info!("Running target program (pid: {})", pid);
            
            // Set up first-chance breakpoint at main if we can find it
            let main_addr = {
                let symbols = self.symbols.lock().unwrap();
                symbols.find_by_name("main").map(|sym| sym.address())
            };
            
            if let Some(addr) = main_addr {
                info!("Setting initial breakpoint at main (0x{:x})", addr);
                self.set_breakpoint(addr)?;
            }
            
            // Continue execution
            self.platform.continue_execution(pid)?;
            self.state = DebuggerState::Running;
            
            // Wait for the process to stop
            if let Err(e) = self.platform.wait_for_stop(pid, 5000) {
                warn!("Error waiting for process to stop: {}", e);
            } else {
                // Process stopped, update state
                self.state = DebuggerState::Stopped;
                
                // Check if we hit a breakpoint
                if let Some(registers) = self.get_registers().ok() {
                    if let Some(pc) = registers.get(crate::debugger::registers::Register::PC) {
                        // In x86, PC would point after the breakpoint instruction
                        // In ARM64, breakpoints are handled differently, but the concept is similar
                        let potential_bp_addr = pc - 1;
                        
                        // Check if we hit a breakpoint and extract needed info first
                        let breakpoint_info = if let Some(bp) = self.find_breakpoint(potential_bp_addr) {
                            // Get the breakpoint address
                            let addr = bp.address();
                            
                            // Get function and source information if available
                            let func_info = self.dwarf_parser.find_function_info(addr).ok().flatten();
                            let line_info = self.dwarf_parser.find_line_info(addr).ok().flatten();
                            
                            Some((addr, func_info, line_info))
                        } else {
                            None
                        };
                        
                        // Now use the collected information without holding a borrow on self
                        if let Some((addr, func_info, line_info)) = breakpoint_info {
                            // Now it's safe to set current_breakpoint
                            self.current_breakpoint = Some(addr);
                            
                            if let Some(func_name) = func_info {
                                if let Some((source_file, line)) = line_info {
                                    info!("Hit breakpoint at {}:{} in function {}", source_file, line, func_name);
                                } else {
                                    info!("Hit breakpoint in function {}", func_name);
                                }
                            } else {
                                // Try to get symbol name from symbol table
                                let symbol_name = {
                                    let symbols = self.symbols.lock().unwrap();
                                    symbols.find_by_address(addr)
                                        .map(|sym| sym.name().to_string())
                                        .unwrap_or_else(|| format!("0x{:x}", addr))
                                };
                                info!("Hit breakpoint at {}", symbol_name);
                            }
                        }
                    }
                }
            }
        } else {
            return Err(anyhow!("Cannot run: program not loaded"));
        }
        
        Ok(())
    }
    
    /// Set a breakpoint at the specified address
    pub fn set_breakpoint(&mut self, address: u64) -> Result<()> {
        if let Some(pid) = self.pid {
            info!("Setting breakpoint at 0x{:x}", address);
            let saved_data = self.platform.set_breakpoint(pid, address)?;
            
            // Create a new breakpoint
            let mut breakpoint = Breakpoint::new(address, saved_data);
            
            // Try to add symbol name information if available
            let symbol_info = {
                let symbols = self.symbols.lock().unwrap();
                symbols.find_by_address_range(address).cloned()
            };
            
            if let Some(symbol) = symbol_info {
                breakpoint.set_symbol_name(Some(symbol.display_name().to_string()));
                
                // Add source location if available
                if let Some(file) = symbol.source_file() {
                    if let Some(line) = symbol.line() {
                        breakpoint.set_source_location(file, line);
                    }
                }
            }
            
            // Add to breakpoint manager
            self.breakpoints.add_breakpoint(breakpoint);
            
            Ok(())
        } else {
            // If program isn't started yet, just record the breakpoint for later
            info!("Queueing breakpoint at 0x{:x} for when program starts", address);
            let breakpoint = Breakpoint::new(address, 0);
            self.breakpoints.add_breakpoint(breakpoint);
            
            Ok(())
        }
    }
    
    /// Set a breakpoint at a function name
    pub fn set_breakpoint_by_name(&mut self, name: &str) -> Result<()> {
        debug!("Setting breakpoint at function: {}", name);
        
        // Try to find the symbol in the symbol table
        let address = {
            let symbols = self.symbols.lock().unwrap();
            symbols.find_by_any_name(name).map(|sym| sym.address())
        };
        
        if let Some(addr) = address {
            info!("Found symbol '{}' at 0x{:x}", name, addr);
            self.set_breakpoint(addr)?;
            Ok(())
        } else {
            Err(anyhow!("Symbol not found: {}", name))
        }
    }

    /// Set a breakpoint at a source file and line number
    pub fn set_breakpoint_by_location(&mut self, file: &str, line: u32) -> Result<()> {
        debug!("Setting breakpoint at {}:{}", file, line);
        
        // Try to find the address for this source location using DWARF info
        if let Some(addr) = self.dwarf_parser.find_address_for_line(file, line)? {
            info!("Found address 0x{:x} for {}:{}", addr, file, line);
            
            // Create a breakpoint
            let mut breakpoint = Breakpoint::new(addr, 0);
            breakpoint.set_source_location(file, line);
            
            // If the program is running, set the real breakpoint
            if let Some(pid) = self.pid {
                let saved_data = self.platform.set_breakpoint(pid, addr)?;
                breakpoint = Breakpoint::new(addr, saved_data);
                breakpoint.set_source_location(file, line);
            }
            
            // Add to breakpoint manager
            self.breakpoints.add_breakpoint(breakpoint);
            
            Ok(())
        } else {
            Err(anyhow!("Could not find address for {}:{}", file, line))
        }
    }
    
    /// Remove a breakpoint at the specified address
    pub fn remove_breakpoint(&mut self, address: u64) -> Result<()> {
        if let Some((index, bp)) = self.breakpoints.find_by_address(address) {
            let saved_data = bp.saved_data();
            
            if let Some(pid) = self.pid {
                info!("Removing breakpoint at 0x{:x}", address);
                self.platform.remove_breakpoint(pid, address, saved_data)?;
            }
            
            // Remove from breakpoint manager
            self.breakpoints.remove_breakpoint(index);
            
            Ok(())
        } else {
            Err(anyhow!("No breakpoint found at address 0x{:x}", address))
        }
    }
    
    /// Remove a breakpoint by ID
    pub fn remove_breakpoint_by_id(&mut self, id: &str) -> Result<()> {
        if let Some((index, bp)) = self.breakpoints.find_by_id(id) {
            let address = bp.address();
            let saved_data = bp.saved_data();
            
            if let Some(pid) = self.pid {
                info!("Removing breakpoint {} at 0x{:x}", id, address);
                self.platform.remove_breakpoint(pid, address, saved_data)?;
            }
            
            // Remove from breakpoint manager
            self.breakpoints.remove_breakpoint(index);
            
            Ok(())
        } else {
            Err(anyhow!("No breakpoint found with ID: {}", id))
        }
    }
    
    /// Find a breakpoint at the specified address
    fn find_breakpoint(&self, address: u64) -> Option<&Breakpoint> {
        self.breakpoints.find_by_address(address).map(|(_, bp)| bp)
    }
    
    /// Get the registers for the current thread
    pub fn get_registers(&self) -> Result<Registers> {
        if let Some(pid) = self.pid {
            self.platform.get_registers(pid)
        } else {
            Err(anyhow!("Cannot get registers: program not loaded"))
        }
    }
    
    /// Set the registers for the current thread
    pub fn set_registers(&self, registers: &Registers) -> Result<()> {
        if let Some(pid) = self.pid {
            self.platform.set_registers(pid, registers)
        } else {
            Err(anyhow!("Cannot set registers: program not loaded"))
        }
    }
    
    /// Update a specific register value
    pub fn update_register(&self, register: Register, value: u64) -> Result<()> {
        if let Some(pid) = self.pid {
            // Get current registers
            let mut registers = self.platform.get_registers(pid)?;
            
            // Update the specific register
            registers.set(register, value);
            
            // Write back the updated registers
            self.platform.set_registers(pid, &registers)
        } else {
            Err(anyhow!("Cannot update register: program not loaded"))
        }
    }
    
    /// Read memory from the target process
    pub fn read_memory(&mut self, address: u64, size: usize) -> Result<Vec<u8>> {
        debug!("Reading {} bytes from 0x{:x}", size, address);
        
        if let Some(pid) = self.pid {
            // Update the memory map if needed
            if self.memory_map.is_none() {
                let mut mem_map = crate::debugger::memory::MemoryMap::new();
                if let Err(e) = mem_map.update_from_process(pid) {
                    warn!("Failed to update memory map: {}", e);
                    // Continue anyway, as we can still try to read memory
                }
                self.memory_map = Some(mem_map);
            }
            
            // Read memory using the platform implementation
            let data = self.platform.read_memory(pid, address, size)?;
            
            // Save the last memory read in our memory map for future reference
            if let Some(mem_map) = &mut self.memory_map {
                mem_map.set_last_dump(address, size);
                
                // Log some info about the region
                if let Some(region) = mem_map.find_region(address) {
                    let description = mem_map.describe_address(address);
                    debug!("Memory region: {}", description);
                    
                    // Print execution warnings
                    if region.protection.can_execute() {
                        debug!("Note: This memory region is executable");
                    }
                }
            }
            
            Ok(data)
        } else {
            Err(anyhow!("No process attached"))
        }
    }
    
    /// Write memory to the target process
    pub fn write_memory(&self, address: u64, data: &[u8]) -> Result<()> {
        if let Some(pid) = self.pid {
            self.platform.write_memory(pid, address, data)
        } else {
            Err(anyhow!("Cannot write memory: program not loaded"))
        }
    }
    
    /// Step a single instruction
    pub fn step(&mut self) -> Result<()> {
        if let Some(pid) = self.pid {
            info!("Stepping instruction");
            
            // If we're at a breakpoint, we need to temporarily remove it,
            // execute the instruction, then restore the breakpoint
            let bp_addr = self.current_breakpoint.take();
            
            if let Some(addr) = bp_addr {
                // Temporarily remove the breakpoint
                let bp = self.find_breakpoint(addr).ok_or_else(|| anyhow!("Breakpoint not found"))?;
                let saved_data = bp.saved_data();
                self.platform.remove_breakpoint(pid, addr, saved_data)?;
                
                // Step one instruction
                self.platform.step(pid)?;
                
                // Restore the breakpoint
                self.platform.set_breakpoint(pid, addr)?;
            } else {
                // No breakpoint, just step
                self.platform.step(pid)?;
            }
            
            // Wait for the process to stop
            if let Err(e) = self.platform.wait_for_stop(pid, 1000) {
                warn!("Error waiting for process to stop after step: {}", e);
            }
            
            self.state = DebuggerState::Stopped;
        } else {
            return Err(anyhow!("Cannot step: program not loaded"));
        }
        
        Ok(())
    }
    
    /// Continue execution from a breakpoint
    pub fn continue_execution(&mut self) -> Result<()> {
        if let Some(pid) = self.pid {
            info!("Continuing execution");
            
            // If we're at a breakpoint, handle it specially
            if let Some(addr) = self.current_breakpoint.take() {
                // Get the breakpoint info
                let bp = self.find_breakpoint(addr).ok_or_else(|| anyhow!("Breakpoint not found"))?;
                let saved_data = bp.saved_data();
                
                // Temporarily remove the breakpoint
                self.platform.remove_breakpoint(pid, addr, saved_data)?;
                
                // Step over the breakpoint
                self.platform.step(pid)?;
                
                // Wait for the step to complete
                if let Err(e) = self.platform.wait_for_stop(pid, 1000) {
                    warn!("Error waiting for process to stop after step: {}", e);
                }
                
                // Restore the breakpoint
                self.platform.set_breakpoint(pid, addr)?;
                
                // Continue execution
                self.platform.continue_execution(pid)?;
            } else {
                // No breakpoint, just continue
                self.platform.continue_execution(pid)?;
            }
            
            self.state = DebuggerState::Running;
        } else {
            return Err(anyhow!("Cannot continue: program not loaded"));
        }
        
        Ok(())
    }
    
    /// Get the current state of the debugger
    pub fn get_state(&self) -> DebuggerState {
        self.state
    }
    
    /// Get the PID of the target process
    pub fn get_pid(&self) -> Option<i32> {
        self.pid
    }
    
    /// Get a reference to the symbol table
    pub fn get_symbols(&self) -> Arc<Mutex<SymbolTable>> {
        Arc::clone(&self.symbols)
    }
    
    /// Get all breakpoints
    pub fn get_breakpoints(&self) -> &[Breakpoint] {
        self.breakpoints.get_all()
    }
    
    /// Get the thread manager
    pub fn get_thread_manager(&self) -> Option<&ThreadManager> {
        Some(&self.thread_manager)
    }
    
    /// Get information about the function at a given address
    pub fn get_function_info(&self, address: u64) -> Result<Option<String>> {
        self.dwarf_parser.find_function_info(address)
    }
    
    /// Get source line information for a given address
    pub fn get_line_info(&self, address: u64) -> Result<Option<(String, u32)>> {
        self.dwarf_parser.find_line_info(address)
    }
    
    /// Get source code lines around a given line
    pub fn get_source_lines(&self, file_path: &str, line: u32, context: u32) -> Result<Vec<(u32, String)>> {
        self.dwarf_parser.get_source_lines(file_path, line, context)
    }

    /// Format memory in different representations
    pub fn format_memory(&self, data: &[u8], format: crate::debugger::memory::MemoryFormat) -> String {
        if let Some(mem_map) = &self.memory_map {
            mem_map.format_memory(data, format)
        } else {
            // Fallback to simple hex formatting
            let mut result = String::new();
            for chunk in data.chunks(16) {
                let hex: Vec<String> = chunk.iter().map(|b| format!("{:02x}", b)).collect();
                result.push_str(&hex.join(" "));
                result.push('\n');
            }
            result
        }
    }

    /// Track a named memory allocation
    pub fn track_allocation(&mut self, name: &str, address: u64, size: u64) -> Result<()> {
        if let Some(mem_map) = &mut self.memory_map {
            mem_map.track_allocation(name, address, size);
            Ok(())
        } else {
            Err(anyhow!("Memory map not initialized"))
        }
    }

    /// Stop tracking a named memory allocation
    pub fn untrack_allocation(&mut self, name: &str) -> Result<bool> {
        if let Some(mem_map) = &mut self.memory_map {
            Ok(mem_map.untrack_allocation(name))
        } else {
            Err(anyhow!("Memory map not initialized"))
        }
    }

    /// Handle a thread stop event
    fn handle_thread_stop(&mut self, tid: u64, address: u64, signal: Option<i32>) -> Result<()> {
        debug!("Thread {} stopped at 0x{:x}", tid, address);
        
        // Update thread state
        let is_at_breakpoint = self.find_breakpoint(address).is_some();
        let thread_state = if is_at_breakpoint {
            ThreadState::AtBreakpoint
        } else if let Some(sig) = signal {
            ThreadState::SignalStop(sig)
        } else {
            ThreadState::Stopped
        };
        
        // Update stop reason
        let stop_reason = if is_at_breakpoint {
            Some(format!("Breakpoint hit at 0x{:x}", address))
        } else if let Some(sig) = signal {
            Some(format!("Signal {} received", sig))
        } else {
            Some("Stopped by debugger".to_string())
        };
        
        // Read thread registers
        // Note: in a real implementation, the platform would have a read_registers function
        // For now, we'll create some dummy registers
        let mut registers = Registers::new();
        registers.set(crate::debugger::registers::Register::PC, address);
        registers.set(crate::debugger::registers::Register::SP, 0xFFFF_FFFF_FFFF_0000);
        registers.set(crate::debugger::registers::Register::X29, 0xFFFF_FFFF_FFFF_0000);
        
        if let Some(thread) = self.thread_manager.get_thread_mut(tid) {
            thread.set_registers(registers);
            thread.set_state(thread_state);
            thread.set_stop_reason(stop_reason);
            
            // Make this the current thread if we don't have one already
            // or if this thread is at a breakpoint (prioritize breakpoints)
            if self.thread_manager.current_thread_id().is_none() || 
               (is_at_breakpoint && !self.thread_manager.any_thread_at_breakpoint()) {
                self.thread_manager.set_current_thread(tid);
            }
            
            // Update call stack if this is important thread (current or at breakpoint)
            if self.thread_manager.current_thread_id() == Some(tid) || is_at_breakpoint {
                if let Ok(stack) = self.build_call_stack(tid) {
                    self.thread_manager.update_call_stack(tid, stack);
                }
            }
        }
        
        // Mark the current breakpoint if at one
        if is_at_breakpoint {
            self.current_breakpoint = Some(address);
        }
        
        Ok(())
    }
    
    /// Build a call stack for a thread
    fn build_call_stack(&self, tid: u64) -> Result<Vec<StackFrame>> {
        debug!("Building call stack for thread {}", tid);
        
        // Get the thread's registers
        let thread = self.thread_manager.get_thread(tid)
            .ok_or_else(|| anyhow!("Thread {} not found", tid))?;
        
        let registers = thread.registers()
            .ok_or_else(|| anyhow!("Thread {} has no register values", tid))?;
        
        // Get program counter, stack pointer, and frame pointer
        let pc = registers.get_program_counter()
            .ok_or_else(|| anyhow!("Unable to read PC register"))?;
        
        let sp = registers.get_stack_pointer()
            .ok_or_else(|| anyhow!("Unable to read SP register"))?;
        
        let fp = registers.get_frame_pointer()
            .ok_or_else(|| anyhow!("Unable to read FP register"))?;
        
        // Start with the current frame
        let mut stack = Vec::new();
        let mut frame_pc = pc;
        let mut frame_sp = sp;
        let mut frame_fp = fp;
        let mut frame_number = 0;
        
        // Add the current frame
        let mut current_frame = StackFrame::new(frame_number, frame_pc, frame_sp, frame_fp);
        
        // Try to get function name and source location
        if let Some(symbol) = {
            let symbols = self.symbols.lock().unwrap();
            symbols.find_by_address_range(frame_pc).cloned()
        } {
            let function_name = symbol.display_name().to_string();
            current_frame = current_frame.with_function(function_name);
            
            if let (Some(file), Some(line)) = (symbol.source_file(), symbol.line()) {
                current_frame = current_frame.with_source_location(file.to_string(), line);
            }
        }
        
        stack.push(current_frame);
        
        // Limit the stack depth to prevent infinite loops from corrupted memory
        const MAX_STACK_FRAMES: usize = 100;
        
        // We'd typically use DWARF info here for unwinding, but for now we'll use
        // a simple frame pointer-based approach for ARM64
        while frame_fp > 0 && stack.len() < MAX_STACK_FRAMES {
            // For ARM64, the frame looks like:
            // [FP, +0]: Previous FP
            // [FP, +8]: Return address (LR)
            
            // Read previous frame pointer
            if let Ok(data) = self.platform.read_memory(
                self.pid.unwrap(), 
                frame_fp, 
                16 // 16 bytes for FP and LR
            ) {
                if data.len() >= 16 {
                    // Extract previous FP and return address
                    let prev_fp = u64::from_le_bytes([
                        data[0], data[1], data[2], data[3], 
                        data[4], data[5], data[6], data[7]
                    ]);
                    
                    let return_addr = u64::from_le_bytes([
                        data[8], data[9], data[10], data[11], 
                        data[12], data[13], data[14], data[15]
                    ]);
                    
                    // If we've reached the end of the stack or have invalid values, break
                    if prev_fp <= frame_fp || return_addr == 0 {
                        break;
                    }
                    
                    // Update frame values
                    frame_pc = return_addr;
                    frame_sp = frame_fp + 16; // Approximate
                    frame_fp = prev_fp;
                    frame_number += 1;
                    
                    // Create new frame
                    let mut next_frame = StackFrame::new(frame_number, frame_pc, frame_sp, frame_fp);
                    
                    // Try to get function name and source location
                    if let Some(symbol) = {
                        let symbols = self.symbols.lock().unwrap();
                        symbols.find_by_address_range(frame_pc).cloned()
                    } {
                        let function_name = symbol.display_name().to_string();
                        next_frame = next_frame.with_function(function_name);
                        
                        if let (Some(file), Some(line)) = (symbol.source_file(), symbol.line()) {
                            next_frame = next_frame.with_source_location(file.to_string(), line);
                        }
                    }
                    
                    stack.push(next_frame);
                } else {
                    break;
                }
            } else {
                // Failed to read memory, stop unwinding
                break;
            }
        }
        
        Ok(stack)
    }

    /// Set a thread-specific breakpoint
    pub fn set_thread_breakpoint(&mut self, address: u64, tid: u64) -> Result<()> {
        // First set a normal breakpoint
        self.set_breakpoint(address)?;
        
        // Then mark it as thread-specific
        if let Some(thread) = self.thread_manager.get_thread_mut(tid) {
            thread.add_breakpoint(address);
            info!("Set thread-specific breakpoint at 0x{:x} for thread {}", address, tid);
            Ok(())
        } else {
            Err(anyhow!("Thread {} not found", tid))
        }
    }
    
    /// Resume a specific thread
    pub fn resume_thread(&mut self, tid: u64) -> Result<()> {
        if let Some(pid) = self.pid {
            if self.thread_manager.resume_thread(tid) {
                // Note: in a real implementation, the platform would have a resume_thread function
                // For now, we'll just log the operation
                info!("Resumed thread {}", tid);
                Ok(())
            } else {
                Err(anyhow!("Thread {} is not suspended", tid))
            }
        } else {
            Err(anyhow!("No process is being debugged"))
        }
    }
    
    /// Suspend a specific thread
    pub fn suspend_thread(&mut self, tid: u64) -> Result<()> {
        if let Some(pid) = self.pid {
            if self.thread_manager.suspend_thread(tid) {
                // Note: in a real implementation, the platform would have a suspend_thread function
                // For now, we'll just log the operation
                info!("Suspended thread {}", tid);
                Ok(())
            } else {
                Err(anyhow!("Thread {} is not running", tid))
            }
        } else {
            Err(anyhow!("No process is being debugged"))
        }
    }
    
    /// Update the list of threads in the target process
    fn update_threads(&mut self) -> Result<()> {
        if let Some(pid) = self.pid {
            // Note: in a real implementation, the platform would have a get_thread_ids function
            // For now, we'll assume we have a single thread with the same ID as the process
            let thread_ids = vec![pid as u64];
            
            debug!("Found {} threads in process {}", thread_ids.len(), pid);
            
            // Update thread manager
            self.thread_manager.update_threads(thread_ids);
            
            Ok(())
        } else {
            Err(anyhow!("No process is being debugged"))
        }
    }
}

impl Drop for Debugger {
    fn drop(&mut self) {
        if let Some(pid) = self.pid {
            info!("Cleaning up debugger, killing process {}", pid);
            if let Err(e) = self.platform.kill(pid) {
                error!("Error killing process: {}", e);
            }
        }
    }
}

// Implement the ConditionEvaluator trait for Debugger
impl ConditionEvaluator for Debugger {
    fn evaluate_condition(&self, expression: &str) -> Result<bool> {
        // This would normally evaluate the expression in the context of the debugged program
        // For now, we'll just return true for any condition
        debug!("Evaluating condition: {}", expression);
        Ok(true)
    }
}
