use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use anyhow::{anyhow, Result};
use log::{info, warn, debug, error};

use crate::debugger::breakpoint::Breakpoint;
use crate::debugger::memory::MemoryMap;
use crate::debugger::registers::Registers;
use crate::debugger::symbols::SymbolTable;
use crate::debugger::threads::ThreadManager;
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
    /// Breakpoints
    breakpoints: Vec<Breakpoint>,
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
            breakpoints: Vec::new(),
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
            self.breakpoints.push(Breakpoint::new(address, saved_data));
        } else {
            // If program isn't started yet, just record the breakpoint for later
            info!("Queueing breakpoint at 0x{:x} for when program starts", address);
            self.breakpoints.push(Breakpoint::new(address, 0));
        }
        
        Ok(())
    }
    
    /// Set a breakpoint at a function name
    pub fn set_breakpoint_by_name(&mut self, name: &str) -> Result<()> {
        debug!("Setting breakpoint at function: {}", name);
        
        // Try to find the symbol in the symbol table
        let address = {
            let symbols = self.symbols.lock().unwrap();
            symbols.find_by_name(name).map(|sym| sym.address())
        };
        
        if let Some(addr) = address {
            info!("Found symbol '{}' at 0x{:x}", name, addr);
            self.set_breakpoint(addr)?;
            Ok(())
        } else {
            Err(anyhow!("Symbol not found: {}", name))
        }
    }
    
    /// Remove a breakpoint at the specified address
    pub fn remove_breakpoint(&mut self, address: u64) -> Result<()> {
        if let Some(index) = self.breakpoints.iter().position(|bp| bp.address() == address) {
            let bp = self.breakpoints.remove(index);
            
            if let Some(pid) = self.pid {
                info!("Removing breakpoint at 0x{:x}", address);
                self.platform.remove_breakpoint(pid, address, bp.saved_data())?;
            }
            
            Ok(())
        } else {
            Err(anyhow!("No breakpoint found at address 0x{:x}", address))
        }
    }
    
    /// Find a breakpoint at the specified address
    fn find_breakpoint(&self, address: u64) -> Option<&Breakpoint> {
        self.breakpoints.iter().find(|bp| bp.address() == address)
    }
    
    /// Get the current registers
    pub fn get_registers(&self) -> Result<Registers> {
        if let Some(pid) = self.pid {
            self.platform.get_registers(pid)
        } else {
            Err(anyhow!("Cannot get registers: program not loaded"))
        }
    }
    
    /// Set the registers
    pub fn set_registers(&self, registers: &Registers) -> Result<()> {
        if let Some(pid) = self.pid {
            self.platform.set_registers(pid, registers)
        } else {
            Err(anyhow!("Cannot set registers: program not loaded"))
        }
    }
    
    /// Read memory from the target process
    pub fn read_memory(&self, address: u64, size: usize) -> Result<Vec<u8>> {
        if let Some(pid) = self.pid {
            self.platform.read_memory(pid, address, size)
        } else {
            Err(anyhow!("Cannot read memory: program not loaded"))
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
        &self.breakpoints
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
