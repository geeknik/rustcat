use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use std::collections::HashMap;
use std::time::Duration;

use anyhow::{anyhow, Result};
use log::{info, warn, debug, error};

use crate::debugger::breakpoint::{Breakpoint, BreakpointManager, ConditionEvaluator, BreakpointType};
use crate::debugger::memory::MemoryMap;
use crate::debugger::registers::{Registers, Register};
use crate::debugger::symbols::SymbolTable;
use crate::debugger::threads::{ThreadManager, ThreadState, StackFrame};
use crate::debugger::disasm::{Disassembler, Instruction};
use crate::debugger::tracer::FunctionTracer;
use crate::debugger::variables::{VariableManager, Variable, VariableValue};
use crate::platform::macos::MacosDebugger;
use crate::platform::dwarf::DwarfParser;
use crate::debugger::breakpoint::{Watchpoint, WatchpointManager};
use crate::debugger::dwarf_controller::DwarfController;

// Add this at the top of the file if not already present
type ProcessId = u64;

/// Debugger state
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
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
    #[allow(dead_code)]
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
    /// Watchpoint manager
    watchpoints: WatchpointManager,
    /// Memory map
    memory_map: Option<MemoryMap>,
    /// Symbol table
    symbols: Arc<Mutex<SymbolTable>>,
    /// Thread manager
    thread_manager: ThreadManager,
    /// DWARF parser for debug information
    dwarf_parser: DwarfParser<'static>,
    /// When the debugging started
    #[allow(dead_code)]
    start_time: Instant,
    /// Current breakpoint address (if stopped at one)
    current_breakpoint: Option<u64>,
    /// Current watchpoint address (if stopped at one)
    current_watchpoint: Option<u64>,
    /// Disassembler for instruction decoding
    disassembler: Disassembler,
    /// Function tracer
    tracer: FunctionTracer,
    /// Variable manager
    variable_manager: VariableManager,
    /// DWARF controller for enhanced debugging
    dwarf_controller: DwarfController,
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
        
        // Create tracer
        let mut tracer = FunctionTracer::new();
        tracer.set_symbol_resolver(Arc::clone(&symbols));
        
        // Create variable manager
        let mut variable_manager = VariableManager::new();
        variable_manager.set_symbol_table(Arc::clone(&symbols));
        
        Ok(Self {
            target_path: target_path.to_string(),
            args: Vec::new(),
            pid: None,
            state: DebuggerState::Idle,
            platform,
            breakpoints: BreakpointManager::new(),
            watchpoints: WatchpointManager::new(),
            memory_map: None,
            symbols,
            thread_manager,
            dwarf_parser: DwarfParser::new(),
            start_time: Instant::now(),
            current_breakpoint: None,
            current_watchpoint: None,
            disassembler: Disassembler::new(),
            tracer,
            variable_manager,
            dwarf_controller: DwarfController::new(),
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
            
            match symbol_table.load_file(std::path::Path::new(&target_path)) {
                Ok(()) => {
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
            warn!("Error loading DWARF debug info with legacy parser: {}", e);
            warn!("Trying with new DWARF controller...");
            
            // Use the new DWARF controller
            match self.dwarf_controller.load_binary(&self.target_path) {
                Ok(_) => {
                    info!("Successfully loaded DWARF debug info with new controller");
                }
                Err(e) => {
                    warn!("Error loading DWARF debug info with new controller: {}", e);
                    warn!("Source-level debugging will be limited");
                }
            }
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
                symbols.find_by_name("main").map(super::symbols::Symbol::address)
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
                if let Ok(registers) = self.get_registers() {
                    if let Some(pc) = registers.get(Register::Pc) {
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
                                    symbols.find_by_address(addr).map_or_else(|| format!("0x{:x}", addr), |sym| sym.name().to_string())
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
            symbols.find_by_any_name(name).map(super::symbols::Symbol::address)
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
        info!("Removing breakpoint at 0x{:x}", address);
        
        // Find the breakpoint by address
        if let Some((index, bp)) = self.breakpoints.find_by_address(address) {
            let saved_data = bp.saved_data();
            
            if let Some(pid) = self.pid {
                self.platform.remove_breakpoint(pid, address, saved_data)?;
            }
            
            // Remove from breakpoint manager
            self.breakpoints.remove_breakpoint(index);
            
            info!("Breakpoint removed successfully");
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
            
            if self.state != DebuggerState::Stopped {
                return Err(anyhow!("Cannot step: program not stopped"));
            }
            
            // Check if we're at a breakpoint
            let is_at_breakpoint = self.current_breakpoint.is_some();
            
            if is_at_breakpoint {
                // Get the current thread ID
                let thread_id = self.thread_manager.current_thread_id().unwrap_or_default();
                
                // If at a breakpoint, we need to:
                // 1. Remove the breakpoint temporarily
                // 2. Step one instruction
                // 3. Re-insert the breakpoint
                // 4. Continue if we're not at the breakpoint anymore
                
                if let Some(bp_addr) = self.current_breakpoint {
                    if let Some((index, bp)) = self.breakpoints.find_by_address(bp_addr) {
                        let saved_data = bp.saved_data();
                        
                        // Remove breakpoint temporarily
                        self.platform.remove_breakpoint(pid, bp_addr, saved_data)?;
                        
                        // Step one instruction
                        self.platform.step(pid)?;
                        
                        // Re-insert breakpoint
                        self.platform.set_breakpoint(pid, bp_addr)?;
                    } else {
                        // No breakpoint, just step
                        self.platform.step(pid)?;
                    }
                }
                
                // Wait for the process to stop again
                if let Err(e) = self.platform.wait_for_stop(pid, 5000) {
                    warn!("Error waiting for process to stop after step: {}", e);
                } else {
                    // Process stopped, update state
                    self.state = DebuggerState::Stopped;
                    
                    // Update thread state
                    if let Ok(registers) = self.get_registers() {
                        let pc = registers.get(Register::Pc).unwrap_or_default();
                        if let Err(e) = self.update_thread_state(thread_id, registers, ThreadState::Stopped, Some(format!("Stepped to 0x{:x}", pc)), pc) {
                            warn!("Error updating thread state: {}", e);
                        }
                    }
                    
                    // Clear current breakpoint if we've moved past it
                    if let Some(regs) = self.thread_manager.get_thread(thread_id).and_then(|t| t.registers()) {
                        let pc = regs.get(Register::Pc).unwrap_or_default();
                        if self.current_breakpoint != Some(pc) {
                            self.current_breakpoint = None;
                        }
                    }
                }
                
                return Ok(());
            } else {
                // Normal step without a breakpoint
                self.platform.step(pid)?;
                
                // Wait for the process to stop
                if let Err(e) = self.platform.wait_for_stop(pid, 5000) {
                    warn!("Error waiting for process to stop after step: {}", e);
                }
                
                // Update thread state
                let thread_id = self.thread_manager.current_thread_id().unwrap_or_default();
                if let Ok(registers) = self.get_registers() {
                    let pc = registers.get(Register::Pc).unwrap_or_default();
                    if let Err(e) = self.update_thread_state(thread_id, registers, ThreadState::Stopped, Some(format!("Stepped to 0x{:x}", pc)), pc) {
                        warn!("Error updating thread state: {}", e);
                    }
                }
                
                return Ok(());
            }
        } else {
            return Err(anyhow!("Cannot step: program not loaded"));
        }
    }
    
    /// Step over a function call
    pub fn step_over(&mut self) -> Result<()> {
        if let Some(pid) = self.pid {
            info!("Stepping over function call");
            
            if self.state != DebuggerState::Stopped {
                return Err(anyhow!("Cannot step over: program not stopped"));
            }
            
            // Get the current thread ID
            let thread_id = self.thread_manager.current_thread_id().unwrap_or_default();
            
            // Get current instruction to see if it's a call
            let pc = if let Ok(regs) = self.get_registers() {
                regs.get(Register::Pc).unwrap_or_default()
            } else {
                return Err(anyhow!("Unable to get current PC register"));
            };
            
            // Disassemble current instruction to check if it's a call
            let instruction = self.disassembler.disassemble_single(pid, pc)?;
            
            if instruction.is_call() {
                // It's a call instruction - we need to:
                // 1. Get the address of the next instruction after the call
                // 2. Set a temporary breakpoint there
                // 3. Continue execution
                // 4. Remove the temporary breakpoint when hit
                
                // Calculate next instruction address (PC + instruction size)
                let next_addr = pc + instruction.size() as u64;
                info!("Setting temporary breakpoint for step-over at 0x{:x}", next_addr);
                
                // Set temporary breakpoint at the return address
                let saved_data = self.platform.set_breakpoint(pid, next_addr)?;
                
                // Create a special "temporary" breakpoint
                let mut temp_bp = Breakpoint::new(next_addr, saved_data);
                temp_bp.set_temp(true);
                
                // Add to breakpoint manager
                let temp_bp_idx = self.breakpoints.add_breakpoint(temp_bp);
                
                // Continue execution
                self.continue_execution()?;
                
                // When we hit the breakpoint, we'll stop, and we should clean up the temp breakpoint
                if self.state == DebuggerState::Stopped && self.current_breakpoint == Some(next_addr) {
                    // Remove the temporary breakpoint
                    if let Err(e) = self.remove_breakpoint(next_addr) {
                        warn!("Error removing temporary breakpoint: {}", e);
                    }
                    
                    info!("Completed step-over operation at 0x{:x}", next_addr);
                }
                
                Ok(())
            } else {
                // Not a call instruction, just do a regular step
                info!("Not a call instruction, performing normal step");
                self.step()
            }
        } else {
            Err(anyhow!("Cannot step over: program not loaded"))
        }
    }
    
    /// Step out of the current function
    pub fn step_out(&mut self) -> Result<()> {
        if let Some(pid) = self.pid {
            info!("Stepping out of current function");
            
            if self.state != DebuggerState::Stopped {
                return Err(anyhow!("Cannot step out: program not stopped"));
            }
            
            // Get the current thread ID
            let thread_id = self.thread_manager.current_thread_id().unwrap_or_default();
            
            // Get the current function's stack frame
            let current_frame = self.thread_manager.get_thread(thread_id)
                .and_then(|t| t.call_stack().first().cloned());
            
            if let Some(frame) = current_frame {
                // Get the return address - in ARM64, the link register (LR) is used for return
                let return_addr = frame.pc; // Assuming the PC field contains the address we need
                
                if return_addr == 0 {
                    return Err(anyhow!("Cannot step out: no valid return address in current frame"));
                }
                
                info!("Setting temporary breakpoint for step-out at return address 0x{:x}", return_addr);
                
                // Set a temporary breakpoint at the return address
                let saved_data = self.platform.set_breakpoint(pid, return_addr)?;
                
                // Create a special "temporary" breakpoint
                let mut temp_bp = Breakpoint::new(return_addr, saved_data);
                temp_bp.set_temp(true);
                
                // Add to breakpoint manager
                let temp_bp_idx = self.breakpoints.add_breakpoint(temp_bp);
                
                // Continue execution
                self.continue_execution()?;
                
                // When we hit the breakpoint, we'll stop, and we should clean up the temp breakpoint
                if self.state == DebuggerState::Stopped && self.current_breakpoint == Some(return_addr) {
                    // Remove the temporary breakpoint
                    if let Err(e) = self.remove_breakpoint(return_addr) {
                        warn!("Error removing temporary breakpoint: {}", e);
                    }
                    
                    info!("Completed step-out operation at 0x{:x}", return_addr);
                }
                
                Ok(())
            } else {
                Err(anyhow!("Cannot step out: no stack frame information available"))
            }
        } else {
            Err(anyhow!("Cannot step out: program not loaded"))
        }
    }
    
    /// Continue execution
    pub fn continue_execution(&mut self) -> Result<()> {
        if let Some(pid) = self.pid {
            info!("Continuing execution of process {}", pid);
            
            // First re-enable any disabled breakpoints
            // Since we're not in a breakpoint context, we need to
            // re-enable them manually
            {
                // First collect all disabled breakpoints to avoid borrowing conflicts
                let disabled_breakpoints: Vec<(usize, u64)> = self.breakpoints.get_all().iter().enumerate()
                    .filter_map(|(index, bp)| {
                        if !bp.is_enabled() {
                            Some((index, bp.address()))
                        } else {
                            None
                        }
                    })
                    .collect();
                
                // Now re-enable each breakpoint
                for (index, address) in disabled_breakpoints {
                    if let Some(bp_mut) = self.breakpoints.get_mut(index) {
                        bp_mut.enable();
                        
                        // Re-enable in the program's memory space
                        self.platform.set_breakpoint(pid, address)?;
                    }
                }
            }
            
            // Actually continue execution
            self.platform.continue_execution(pid)?;
            self.state = DebuggerState::Running;
            
            // Wait for the process to stop
            if let Err(e) = self.platform.wait_for_stop(pid, 0) {
                error!("Error waiting for process to stop: {}", e);
                // Do not return an error here, since this could be normal
                // (e.g., process exited, timed out, etc.)
            } else {
                // Process stopped, update state
                self.state = DebuggerState::Stopped;
                
                // Check if we hit a breakpoint
                if let Some(pc) = self.check_breakpoints()? {
                    // We hit a breakpoint
                    self.current_breakpoint = Some(pc);
                    // Return success since this is expected
                    return Ok(());
                }
                
                // Check if we hit a watchpoint
                if let Some(addr) = self.check_watchpoints()? {
                    // We hit a watchpoint
                    self.current_watchpoint = Some(addr);
                    // Return success
                    return Ok(());
                }
                
                // We hit something else (maybe a signal)
                info!("Process stopped (not at a breakpoint or watchpoint)");
            }
            
            Ok(())
        } else {
            Err(anyhow!("No process to continue"))
        }
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
    pub fn get_function_info(&self, _address: u64) -> Result<Option<String>> {
        // Just return None for now - will be implemented when DWARF parsing is complete
        Ok(None)
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
    #[allow(dead_code)]
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
        registers.set(crate::debugger::registers::Register::Pc, address);
        registers.set(crate::debugger::registers::Register::Sp, 0xFFFF_FFFF_FFFF_0000);
        registers.set(crate::debugger::registers::Register::X29, 0xFFFF_FFFF_FFFF_0000);
        
        if let Some(thread) = self.thread_manager.get_thread_mut(tid) {
            thread.set_registers(registers);
            thread.set_state(thread_state);
            thread.set_stop_reason(stop_reason);
            
            // Make this the current thread if we don't have one already
            // or if this thread is at a breakpoint (prioritize breakpoints)
            if self.thread_manager.current_thread_id().is_none() || 
               (is_at_breakpoint && !self.thread_manager.any_thread_at_breakpoint()) {
                let _ = self.thread_manager.set_current_thread(tid);
            }
            
            // Update call stack if this is important thread (current or at breakpoint)
            if self.thread_manager.current_thread_id() == Some(tid) || is_at_breakpoint {
                if let Ok(stack) = self.build_call_stack(tid) {
                    let _ = self.thread_manager.update_call_stack(tid, stack);
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
    #[allow(dead_code)]
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
        let mut frame_pointer = fp;
        let mut frame_number = 0;
        
        // Add the current frame
        let mut current_frame = StackFrame::new(frame_number, frame_pc, frame_sp, frame_pointer);
        
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
        while frame_pointer > 0 && stack.len() < MAX_STACK_FRAMES {
            // For ARM64, the frame looks like:
            // [FP, +0]: Previous FP
            // [FP, +8]: Return address (LR)
            
            // Read previous frame pointer
            if let Ok(data) = self.platform.read_memory(
                self.pid.unwrap(), 
                frame_pointer, 
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
                    if prev_fp <= frame_pointer || return_addr == 0 {
                        break;
                    }
                    
                    // Update frame values
                    frame_pc = return_addr;
                    frame_sp = frame_pointer + 16; // Approximate
                    frame_pointer = prev_fp;
                    frame_number += 1;
                    
                    // Create new frame
                    let mut next_frame = StackFrame::new(frame_number, frame_pc, frame_sp, frame_pointer);
                    
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
        if let Some(_pid) = self.pid {
            if self.thread_manager.resume_thread(tid)? {
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
        if let Some(_pid) = self.pid {
            if self.thread_manager.suspend_thread(tid)? {
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
    #[allow(dead_code)]
    fn update_threads(&mut self) -> Result<()> {
        if let Some(pid) = self.pid {
            // Note: in a real implementation, the platform would have a get_thread_ids function
            // For now, we'll assume we have a single thread with the same ID as the process
            let thread_ids = vec![pid as u64];
            
            debug!("Found {} threads in process {}", thread_ids.len(), pid);
            
            // Update thread manager
            let _ = self.thread_manager.update_threads(thread_ids);
            
            Ok(())
        } else {
            Err(anyhow!("No process is being debugged"))
        }
    }

    /// Disassemble instructions at a specific address
    pub fn disassemble(&self, address: u64, count: usize) -> Result<Vec<Instruction>> {
        if let Some(_pid) = self.pid {
            // Disassemble using our disassembler
            let instructions = self.disassembler.disassemble(address, count)?;
            
            // Check if any of these addresses have breakpoints
            let result = instructions.into_iter().map(|mut ins| {
                // Mark instructions that have breakpoints
                if self.find_breakpoint(ins.address).is_some() {
                    // This is a simple way to mark it in the display text
                    ins.text = format!("* {}", ins.text);
                }
                ins
            }).collect();
            
            Ok(result)
        } else {
            Err(anyhow!("Cannot disassemble: program not loaded"))
        }
    }
    
    /// Disassemble at current position
    pub fn disassemble_current(&self, count: usize) -> Result<Vec<Instruction>> {
        // Get the current PC value from registers
        if let Ok(registers) = self.get_registers() {
            if let Some(pc) = registers.get(Register::Pc) {
                // Disassemble at the current PC
                self.disassemble(pc, count)
            } else {
                Err(anyhow!("Cannot determine current PC value"))
            }
        } else {
            Err(anyhow!("Cannot get registers to determine PC"))
        }
    }
    
    /// Get disassembly context for a specific address
    /// Returns instructions before and after the address
    pub fn get_disassembly_context(&self, address: u64, 
                                   context_before: usize, 
                                   context_after: usize) -> Result<Vec<Instruction>> {
        // For simplicity, we'll disassemble from an earlier point to get the context
        // This is approximate since instruction lengths can vary, but for ARM64 they're fixed at 4 bytes
        let start_address = address.saturating_sub((context_before * 4) as u64);
        let total_count = context_before + 1 + context_after;
        
        self.disassemble(start_address, total_count)
    }

    // Function tracer methods

    /// Enable function call tracing
    pub fn enable_function_tracing(&mut self) {
        self.tracer.enable();
    }

    /// Disable function call tracing
    pub fn disable_function_tracing(&mut self) {
        self.tracer.disable();
    }

    /// Clear function call trace
    pub fn clear_function_trace(&mut self) {
        self.tracer.clear();
    }

    /// Add a function filter for tracing
    pub fn add_function_trace_filter(&mut self, pattern: String) {
        self.tracer.add_function_filter(pattern);
    }

    /// Clear all function trace filters
    pub fn clear_function_trace_filters(&mut self) {
        self.tracer.clear_function_filters();
    }

    /// Set maximum number of function calls to trace
    pub fn set_max_traced_calls(&mut self, max_calls: usize) {
        self.tracer.set_max_calls(max_calls);
    }

    /// Record a function call
    pub fn record_function_call(&mut self, call_site: u64, function_address: u64, thread_id: u64) -> Result<usize> {
        self.tracer.record_call(call_site, function_address, thread_id)
    }

    /// Record a function return
    pub fn record_function_return(&mut self, thread_id: u64, return_value: Option<u64>) -> Result<()> {
        self.tracer.record_return(thread_id, return_value)
    }

    /// Check if function tracing is enabled
    pub fn is_function_tracing_enabled(&self) -> bool {
        self.tracer.is_enabled()
    }

    /// Get all traced function calls
    pub fn get_traced_calls(&self) -> &[crate::debugger::tracer::FunctionCall] {
        self.tracer.get_calls()
    }

    /// Get the call tree for a specific thread
    pub fn get_function_call_tree(&self, thread_id: u64) -> Vec<String> {
        self.tracer.format_call_tree(thread_id)
    }

    /// Get function call statistics
    pub fn get_function_call_stats(&self) -> HashMap<String, (usize, Duration)> {
        self.tracer.get_statistics()
    }

    /// Get all variables in a specific stack frame
    pub fn get_variables_by_frame(&self, frame_index: usize) -> Vec<&Variable> {
        self.variable_manager.get_variables_by_frame(frame_index)
    }

    /// Evaluate a variable expression
    pub fn evaluate_expression(&mut self, expression: &str) -> Result<VariableValue> {
        if expression.trim().is_empty() {
            return Err(anyhow!("Empty expression"));
        }
        
        // Use process ID if available, otherwise pass 0 as a placeholder
        let pid = self.pid.unwrap_or(0);
        
        // Attempt to evaluate the expression using the variable manager
        let result = self.variable_manager.evaluate_expression(expression, pid);
        
        // Log the evaluation attempt
        match &result {
            Ok(value) => debug!("Evaluated expression '{}' = {:?}", expression, value),
            Err(e) => debug!("Failed to evaluate expression '{}': {}", expression, e),
        }
        
        result
    }

    /// Add a variable for inspection
    pub fn add_variable(&mut self, variable: Variable) {
        self.variable_manager.add_variable(variable);
    }

    /// Set a hardware watchpoint
    pub fn set_hardware_watchpoint(&mut self, address: u64, size: usize, watchpoint_type: crate::platform::WatchpointType) -> Result<()> {
        if let Some(pid) = self.pid {
            info!("Setting hardware watchpoint at 0x{:x} (size: {})", address, size);
            
            if let Ok(threads) = self.get_threads() {
                if threads.is_empty() {
                    return Err(anyhow!("No threads available"));
                }
                
                let thread_id = threads[0].tid();
                let register_index = self.platform.set_watchpoint(pid, thread_id, address, size, watchpoint_type)?;
                
                // Create a new breakpoint object
                let mut breakpoint = Breakpoint::new_with_type(address, 0, BreakpointType::Hardware);
                
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
                
                // Store hardware register information in the breakpoint
                // We'll use the id field to store the register index
                breakpoint.set_id(Some(format!("hw{}", register_index)));
                
                // Add to breakpoint manager
                self.breakpoints.add_breakpoint(breakpoint);
                
                info!("Hardware watchpoint set at 0x{:x}, size: {}, type: {}, register: {}", 
                      address, size, watchpoint_type.as_str(), register_index);
                
                Ok(())
            } else {
                return Err(anyhow!("Failed to get thread list"));
            }
        } else {
            Err(anyhow!("No process to debug"))
        }
    }
    
    /// Remove a hardware watchpoint
    pub fn remove_hardware_watchpoint(&mut self, address: u64) -> Result<()> {
        if let Some(pid) = self.pid {
            // Get current thread
            if let Ok(threads) = self.platform.get_threads(pid) {
                if !threads.is_empty() {
                    let _thread_id = threads[0];
                    
                    // Remove the hardware watchpoint
                    // self.platform.remove_hardware_watchpoint(pid, thread_id, address as usize)?;
                    
                    // Remove from breakpoint manager
                    self.breakpoints.remove_breakpoint(address as usize).ok_or_else(|| anyhow!("No breakpoint found at address"))?;
                    
                    info!("Removed hardware watchpoint at 0x{:x}", address);
                    
                    return Ok(());
                }
            }
            
            return Err(anyhow!("No threads available to remove hardware watchpoint"));
        }
        
        Err(anyhow!("No process attached"))
    }
    
    /// Remove a watchpoint by ID
    pub fn remove_watchpoint_by_id(&mut self, id: &str) -> Result<()> {
        info!("Removing watchpoint with ID: {}", id);
        
        // Find the watchpoint with this ID
        let (index, watchpoint) = match self.watchpoints.find_by_id(id) {
            Some((idx, wp)) => (idx, wp),
            None => return Err(anyhow!("No watchpoint found with ID: {}", id)),
        };
        
        // Get register index
        let _register_index = match watchpoint.register_index() {
            Some(idx) => idx,
            None => return Err(anyhow!("Watchpoint has no hardware register assigned")),
        };
        
        // Get process ID
        let _pid = match self.pid {
            Some(pid) => pid,
            None => return Err(anyhow!("No process to debug")),
        };
        
        // Remove hardware watchpoint
        // self.platform.remove_hardware_watchpoint(pid, register_index)?;
        
        // Remove from our manager
        self.watchpoints.remove_watchpoint(index);
        
        info!("Watchpoint removed with ID: {}", id);
        
        Ok(())
    }
    
    /// Get all watchpoints
    pub fn get_watchpoints(&self) -> &[Watchpoint] {
        self.watchpoints.get_all()
    }

    /// Set a hardware breakpoint at the specified address
    pub fn set_hardware_breakpoint(&mut self, address: u64) -> Result<()> {
        if let Some(_pid) = self.pid {
            info!("Setting hardware breakpoint at 0x{:x}", address);
            
            // Get the current thread
            let threads = self.thread_manager.get_threads();
            if threads.is_empty() {
                return Err(anyhow!("No threads available"));
            }
            
            let _thread_id = threads[0].tid();
            
            // TODO: Implement hardware breakpoints
            // For now, we'll just set a software breakpoint
            self.set_breakpoint(address)?;
            
            Ok(())
        } else {
            Err(anyhow!("Cannot set hardware breakpoint: process not running"))
        }
    }
    
    /// Set a conditional breakpoint
    pub fn set_conditional_breakpoint(&mut self, address: u64, condition: &str) -> Result<()> {
        if condition.trim().is_empty() {
            return Err(anyhow!("Empty condition"));
        }
        
        // First set a regular breakpoint
        self.set_breakpoint(address)?;
        
        // Find the breakpoint we just set and modify it
        if let Some((index, _)) = self.breakpoints.find_by_address(address) {
            if let Some(bp) = self.breakpoints.get_mut(index) {
                // Set the condition and type
                bp.set_condition(Some(condition.to_string()));
                bp.set_breakpoint_type(BreakpointType::Conditional);
                
                info!("Set conditional breakpoint at 0x{:x} with condition: {}", address, condition);
                Ok(())
            } else {
                Err(anyhow!("Failed to get breakpoint after setting it"))
            }
        } else {
            Err(anyhow!("Failed to find breakpoint after setting it"))
        }
    }
    
    /// Set a one-shot breakpoint (auto-delete on hit)
    pub fn set_one_shot_breakpoint(&mut self, address: u64) -> Result<()> {
        // First set a regular breakpoint
        self.set_breakpoint(address)?;
        
        // Find the breakpoint we just set and modify it
        if let Some((index, _)) = self.breakpoints.find_by_address(address) {
            if let Some(bp) = self.breakpoints.get_mut(index) {
                // Set as one-shot breakpoint
                bp.set_breakpoint_type(BreakpointType::OneShot);
                
                info!("Set one-shot breakpoint at 0x{:x}", address);
                Ok(())
            } else {
                Err(anyhow!("Failed to get breakpoint after setting it"))
            }
        } else {
            Err(anyhow!("Failed to find breakpoint after setting it"))
        }
    }
    
    /// Set a logging breakpoint (doesn't stop execution)
    pub fn set_logging_breakpoint(&mut self, address: u64, message: &str) -> Result<()> {
        // First set a regular breakpoint
        self.set_breakpoint(address)?;
        
        // Find the breakpoint we just set and modify it
        if let Some((index, _)) = self.breakpoints.find_by_address(address) {
            if let Some(bp) = self.breakpoints.get_mut(index) {
                // Set as logging breakpoint
                bp.set_breakpoint_type(BreakpointType::Logging);
                bp.set_log_message(Some(message.to_string()));
                
                info!("Set logging breakpoint at 0x{:x} with message: {}", address, message);
                Ok(())
            } else {
                Err(anyhow!("Failed to get breakpoint after setting it"))
            }
        } else {
            Err(anyhow!("Failed to find breakpoint after setting it"))
        }
    }
    
    /// Set a count-based breakpoint (stop only after N hits)
    pub fn set_count_breakpoint(&mut self, address: u64, count: usize) -> Result<()> {
        if count == 0 {
            return Err(anyhow!("Count must be greater than 0"));
        }
        
        // First set a regular breakpoint
        self.set_breakpoint(address)?;
        
        // Find the breakpoint we just set and modify it
        if let Some((index, _)) = self.breakpoints.find_by_address(address) {
            if let Some(bp) = self.breakpoints.get_mut(index) {
                // Set the ignore count
                bp.set_ignore_count(count - 1);
                
                info!("Set count-based breakpoint at 0x{:x} to trigger after {} hits", address, count);
                Ok(())
            } else {
                Err(anyhow!("Failed to get breakpoint after setting it"))
            }
        } else {
            Err(anyhow!("Failed to find breakpoint after setting it"))
        }
    }
    
    /// Check if the current stop is due to a hardware breakpoint
    fn check_hardware_breakpoints(&mut self) -> Result<Option<u64>> {
        if let Some(_pid) = self.pid {
            let threads = self.thread_manager.get_threads();
            if threads.is_empty() {
                return Ok(None);
            }
            
            // Check all threads for hardware breakpoint hits
            for thread in threads {
                if let Ok(Some((register_index, address))) = self.platform.is_hardware_watchpoint_hit(_pid, thread.thread_id()) {
                    info!("Hardware breakpoint hit at 0x{:x} (register #{})", address, register_index);
                    
                    // Find the corresponding breakpoint in our tracking
                    let bp_id = format!("hw{}", register_index);
                    
                    // Check if we have a breakpoint with this ID
                    if let Some((index, _)) = self.breakpoints.find_by_id(&bp_id) {
                        // First handle disabled status
                        let is_enabled = {
                            let bp = self.breakpoints.get(index).ok_or_else(|| anyhow!("Breakpoint not found"))?;
                            bp.is_enabled()
                        };
                        
                        if is_enabled {
                            // Must be in its own scope to avoid borrow conflicts
                            {
                                let bp = self.breakpoints.get_mut(index).ok_or_else(|| anyhow!("Breakpoint not found"))?;
                                bp.disable();
                            }
                            
                            // Now remove the hardware breakpoint
                            self.remove_hardware_breakpoint(address)?;
                        }
                        
                        // Extract all info needed for decision making
                        let (bp_type, condition, log_message) = {
                            let bp = self.breakpoints.get(index).ok_or_else(|| anyhow!("Breakpoint not found"))?;
                            (
                                bp.breakpoint_type(),
                                bp.condition().clone().unwrap_or_default(),
                                bp.log_message().clone().unwrap_or_default()
                            )
                        };
                        
                        // Now handle different breakpoint types
                        match bp_type {
                            BreakpointType::Conditional => {
                                match self.evaluate_condition(&condition) {
                                    Ok(true) => {
                                        // Record hit in its own scope
                                        {
                                            let bp = self.breakpoints.get_mut(index).ok_or_else(|| anyhow!("Breakpoint not found"))?;
                                            bp.hit();
                                        }
                                        self.state = DebuggerState::Stopped;
                                    },
                                    Ok(false) => {
                                        self.continue_execution()?;
                                    },
                                    Err(e) => {
                                        error!("Error evaluating condition: {}", e);
                                        // Record hit in its own scope
                                        {
                                            let bp = self.breakpoints.get_mut(index).ok_or_else(|| anyhow!("Breakpoint not found"))?;
                                            bp.hit();
                                        }
                                        self.state = DebuggerState::Stopped;
                                    }
                                }
                            },
                            BreakpointType::Logging => {
                                info!("Breakpoint hit: {}", log_message);
                                self.continue_execution()?;
                            },
                            _ => {
                                // Record hit in its own scope
                                {
                                    let bp = self.breakpoints.get_mut(index).ok_or_else(|| anyhow!("Breakpoint not found"))?;
                                    bp.hit();
                                }
                                self.state = DebuggerState::Stopped;
                            }
                        }
                    }
                    
                    return Ok(Some(address));
                }
            }
        }
        
        
        Ok(None)
    }
    
    /// Remove a hardware breakpoint at the specified address
    pub fn remove_hardware_breakpoint(&mut self, address: u64) -> Result<()> {
        if let Some(_pid) = self.pid {
            // Find the hardware breakpoint by address
            let mut index_to_remove = None;
            let mut register_index = None;
            
            // Search for a hardware breakpoint at this address
            for (idx, bp) in self.breakpoints.get_all().iter().enumerate() {
                if bp.address() == address && bp.breakpoint_type() == BreakpointType::Hardware {
                    if let Some(id) = bp.id() {
                        if id.starts_with("hw") {
                            if let Ok(reg_idx) = id[2..].parse::<usize>() {
                                index_to_remove = Some(idx);
                                register_index = Some(reg_idx);
                                break;
                            }
                        }
                    }
                }
            }
            
            if let (Some(idx), Some(_reg_idx)) = (index_to_remove, register_index) {
                // Get thread ID for the operation
                let threads = self.thread_manager.get_threads();
                if threads.is_empty() {
                    return Err(anyhow!("No threads available"));
                }
                
                let _thread_id = threads[0].thread_id();
                
                // Remove the hardware breakpoint
                // self.platform.remove_hardware_breakpoint(pid, thread_id, reg_idx)?;
                
                // Remove from breakpoint manager
                self.breakpoints.remove_breakpoint(idx);
                
                info!("Removed hardware breakpoint at 0x{:x}", address);
                Ok(())
            } else {
                Err(anyhow!("No hardware breakpoint found at address 0x{:x}", address))
            }
        } else {
            Err(anyhow!("Cannot remove hardware breakpoint: process not running"))
        }
    }

    /// Get a list of threads
    pub fn get_threads(&self) -> Result<Vec<&crate::debugger::threads::Thread>> {
        Ok(self.thread_manager.get_threads())
    }

    /// Check if the current stop is due to a breakpoint
    fn check_breakpoints(&mut self) -> Result<Option<u64>> {
        if let Some(_pid) = self.pid {
            let threads = self.thread_manager.get_threads();
            if threads.is_empty() {
                return Ok(None);
            }
            
            // Check all threads for breakpoint hits
            for thread in threads {
                let pc = self.platform.get_program_counter(_pid, thread.thread_id())?;
                
                if let Some(index) = self.breakpoints.find_index(pc) {
                    // First handle disabled status
                    let is_enabled = {
                        let bp = self.breakpoints.get(index).ok_or_else(|| anyhow!("Breakpoint not found"))?;
                        bp.is_enabled()
                    };
                    
                    if is_enabled {
                        // Must be in its own scope to avoid borrow conflicts
                        {
                            let bp = self.breakpoints.get_mut(index).ok_or_else(|| anyhow!("Breakpoint not found"))?;
                            bp.disable();
                        }
                        
                        // Now remove the hardware breakpoint
                        self.remove_hardware_breakpoint(pc)?;
                    }
                    
                    // Extract all info needed for decision making
                    let (bp_type, condition, log_message) = {
                        let bp = self.breakpoints.get(index).ok_or_else(|| anyhow!("Breakpoint not found"))?;
                        (
                            bp.breakpoint_type(),
                            bp.condition().clone().unwrap_or_default(),
                            bp.log_message().clone().unwrap_or_default()
                        )
                    };
                    
                    // Now handle different breakpoint types
                    match bp_type {
                        BreakpointType::Conditional => {
                            match self.evaluate_condition(&condition) {
                                Ok(true) => {
                                    // Record hit in its own scope
                                    {
                                        let bp = self.breakpoints.get_mut(index).ok_or_else(|| anyhow!("Breakpoint not found"))?;
                                        bp.hit();
                                    }
                                    self.state = DebuggerState::Stopped;
                                },
                                Ok(false) => {
                                    self.continue_execution()?;
                                },
                                Err(e) => {
                                    error!("Error evaluating condition: {}", e);
                                    // Record hit in its own scope
                                    {
                                        let bp = self.breakpoints.get_mut(index).ok_or_else(|| anyhow!("Breakpoint not found"))?;
                                        bp.hit();
                                    }
                                    self.state = DebuggerState::Stopped;
                                }
                            }
                        },
                        BreakpointType::Logging => {
                            info!("Breakpoint hit: {}", log_message);
                            self.continue_execution()?;
                        },
                        _ => {
                            // Record hit in its own scope
                            {
                                let bp = self.breakpoints.get_mut(index).ok_or_else(|| anyhow!("Breakpoint not found"))?;
                                bp.hit();
                            }
                            self.state = DebuggerState::Stopped;
                        }
                    }
                    
                    return Ok(Some(pc));
                }
            }
        }
        
        Ok(None)
    }

    /// Check if the current stop is due to a watchpoint
    fn check_watchpoints(&mut self) -> Result<Option<u64>> {
        if let Some(pid) = self.pid {
            let threads = self.thread_manager.get_threads();
            if threads.is_empty() {
                return Ok(None);
            }
            
            // Check all threads for watchpoint hits
            for thread in threads {
                if let Ok(Some((register_index, address))) = self.platform.is_hardware_watchpoint_hit(pid, thread.thread_id()) {
                    info!("Hardware watchpoint hit at 0x{:x} (register #{})", address, register_index);
                    
                    // Find the corresponding watchpoint in our tracking
                    let wp_id = format!("wp{}", register_index);
                    
                    if let Some((index, _)) = self.watchpoints.find_by_id(&wp_id) {
                        // First handle disabled status
                        let is_enabled = {
                            let wp = self.watchpoints.get(index).ok_or_else(|| anyhow!("Watchpoint not found"))?;
                            wp.is_enabled()
                        };
                        
                        if is_enabled {
                            // Must be in its own scope to avoid borrow conflicts
                            {
                                let wp = self.watchpoints.get_mut(index).ok_or_else(|| anyhow!("Watchpoint not found"))?;
                                wp.disable();
                            }
                            
                            // Now remove the hardware watchpoint
                            self.remove_hardware_watchpoint(address)?;
                        }
                        
                        // Extract all info needed for decision making
                        let (wp_type, condition, log_message) = {
                            let wp = self.watchpoints.get(index).ok_or_else(|| anyhow!("Watchpoint not found"))?;
                            (
                                wp.watchpoint_type(),
                                wp.condition().clone().unwrap_or_default(),
                                wp.log_message().clone().unwrap_or_default()
                            )
                        };
                        
                        // Now handle different watchpoint types
                        match wp_type {
                            crate::platform::WatchpointType::Conditional => {
                                match self.evaluate_condition(&condition) {
                                    Ok(true) => {
                                        // Record hit in its own scope
                                        {
                                            let wp = self.watchpoints.get_mut(index).ok_or_else(|| anyhow!("Watchpoint not found"))?;
                                            wp.hit();
                                        }
                                        self.state = DebuggerState::Stopped;
                                    },
                                    Ok(false) => {
                                        self.continue_execution()?;
                                    },
                                    Err(e) => {
                                        error!("Error evaluating condition: {}", e);
                                        // Record hit in its own scope
                                        {
                                            let wp = self.watchpoints.get_mut(index).ok_or_else(|| anyhow!("Watchpoint not found"))?;
                                            wp.hit();
                                        }
                                        self.state = DebuggerState::Stopped;
                                    }
                                }
                            },
                            crate::platform::WatchpointType::Logging => {
                                info!("Watchpoint hit: {}", log_message);
                                self.continue_execution()?;
                            },
                            _ => {
                                // Record hit in its own scope
                                {
                                    let wp = self.watchpoints.get_mut(index).ok_or_else(|| anyhow!("Watchpoint not found"))?;
                                    wp.hit();
                                }
                                self.state = DebuggerState::Stopped;
                            }
                        }
                    }
                    
                    return Ok(Some(address));
                }
            }
        }
        
        Ok(None)
    }

    /// Load symbols from a goblin-parsed Mach-O binary
    #[cfg(feature = "macho")]
    pub fn load_macho_symbols(&mut self, macho_data: &[u8]) -> Result<()> {
        // This implementation is currently disabled due to Symbol type errors
        // Will be implemented fully when DWARF integration is complete
        info!("Macho symbol loading disabled during DWARF task restructuring");
        Ok(())
    }
    
    /// Get access to the DWARF controller
    pub fn get_dwarf_controller(&self) -> &DwarfController {
        &self.dwarf_controller
    }
    
    /// Set the source root directory for resolving DWARF source paths
    pub fn set_source_root<P: AsRef<Path>>(&mut self, path: P) -> Result<()> {
        self.dwarf_controller.set_source_root(path)
    }
    
    /// Get DWARF source context for the current instruction pointer
    pub fn get_current_source_context(&self, _context_lines: usize) -> Result<(String, Vec<(u64, String, bool)>)> {
        // Return an empty result for now - will be implemented when DWARF parsing is complete
        Err(anyhow!("DWARF source context not yet implemented"))
    }
    
    /// Get DWARF variable information for the current function
    pub fn get_dwarf_variables(&self) -> Result<Vec<(String, String)>> {
        // Return an empty result for now - will be implemented when DWARF parsing is complete
        Ok(Vec::new())
    }
    
    /// Check if DWARF debug info is loaded
    pub fn is_dwarf_loaded(&self) -> bool {
        self.dwarf_controller.is_loaded()
    }
    
    /// Get the DWARF parsing progress (0.0 to 1.0)
    pub fn get_dwarf_progress(&self) -> f32 {
        self.dwarf_controller.get_progress()
    }

    /// Evaluate a log message with any embedded expressions
    fn evaluate_log_message(&self, message: &str) -> Result<String> {
        // Simple implementation that returns the message as is
        // In a more complete implementation, this would evaluate expressions in the message
        Ok(message.to_string())
    }

    /// Disable a breakpoint at the specified address without removing it
    fn disable_breakpoint_by_address(&mut self, address: u64) -> Result<()> {
        // Find the breakpoint by address
        if let Some((index, _)) = self.breakpoints.find_by_address(address) {
            // Get a mutable reference to the breakpoint
            let bp = self.breakpoints.get_mut(index).ok_or_else(|| anyhow!("Breakpoint not found"))?;
            // Set enabled to false
            bp.disable();
            info!("Breakpoint at 0x{:x} disabled", address);
            return Ok(());
        }
        
        Err(anyhow!("No breakpoint found at address 0x{:x}", address))
    }

    /// Update the state of a thread
    fn update_thread_state(&mut self, thread_id: u64, registers: Registers, state: ThreadState, stop_reason: Option<String>, address: u64) -> Result<()> {
        let is_at_breakpoint = self.breakpoints.find_by_address(address).is_some();
        
        if let Some(thread) = self.thread_manager.get_thread_mut(thread_id) {
            thread.set_registers(registers);
            thread.set_state(state);
            thread.set_stop_reason(stop_reason);
            
            // Make this the current thread if we don't have one already
            // or if this thread is at a breakpoint (prioritize breakpoints)
            if self.thread_manager.current_thread_id().is_none() || 
               (is_at_breakpoint && !self.thread_manager.any_thread_at_breakpoint()) {
                let _ = self.thread_manager.set_current_thread(thread_id);
            }
            
            // Update call stack if this is important thread (current or at breakpoint)
            if self.thread_manager.current_thread_id() == Some(thread_id) || is_at_breakpoint {
                if let Ok(stack) = self.build_call_stack(thread_id) {
                    let _ = self.thread_manager.update_call_stack(thread_id, stack);
                }
            }
        }
        
        // Mark the current breakpoint if at one
        if is_at_breakpoint {
            self.current_breakpoint = Some(address);
        }
        
        Ok(())
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

