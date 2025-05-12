#![allow(clippy::struct_excessive_bools)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::uninlined_format_args)]
#![allow(clippy::significant_drop_tightening)]
#![allow(clippy::cognitive_complexity)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::unnecessary_wraps)]
#![allow(clippy::option_if_let_else)]
#![allow(clippy::indexing_slicing)]
#![allow(clippy::match_same_arms)]
#![allow(clippy::used_underscore_binding)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::needless_pass_by_value)]
#![allow(clippy::branches_sharing_code)]
#![allow(clippy::equatable_if_let)]
#![allow(clippy::must_use_candidate)]

use std::sync::{Arc, Mutex};
use std::collections::{VecDeque, HashMap};
use std::time::{Duration, Instant};
use std::sync::mpsc;
use std::fs::File;
use std::io::Write;

use anyhow::{Result, Context, anyhow};
use crossterm::event::{Event, KeyCode, KeyModifiers, MouseEventKind, MouseButton, KeyEvent};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen};
use crossterm::execute;
use crossterm::event::EnableMouseCapture;
use crossterm::event::DisableMouseCapture;
use log::{debug, info, warn, error};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::Terminal;
use regex::Regex;

use crate::debugger::core::{Debugger, DebuggerState};
use crate::debugger::breakpoint::Breakpoint;
use crate::debugger::memory::{MemoryFormat, SearchPattern, SearchResult};
use crate::tui::ui::draw_ui;
use crate::tui::ui::setup_log_capture;
use crate::tui::events::Events;
use crate::debugger::registers::Registers;
use crate::debugger::threads::{ThreadState, StackFrame};
use crate::platform::WatchpointType;

/// UI active block (for focus handling)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActiveBlock {
    MainView,
    CommandInput,
    LogView,
}

/// Log message severity level filter 
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogFilter {
    Debug,
    Info,
    Warn,
    Error,
    Custom,
}

/// UI Mode for specialized actions
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UiMode {
    Normal,
    LogSearch,
    ContextMenu,
    BreakpointManager,
    CommandHelp,
    CommandCompletion,
    HelpOverlay,
}

/// Context menu action
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContextMenuAction {
    SetBreakpoint,
    ClearBreakpoint,
    RunToCursor,
    Copy,
    ViewMemory(u64),
    SaveToFile,
    // Nested menu
    Submenu(String, Vec<ContextMenuAction>),
}

/// Command type for proper parsing and execution
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    // Debug commands
    Break(String),         // Set breakpoint at address or function
    Continue,              // Continue execution
    Step,                  // Step into
    Next,                  // Step over
    Finish,                // Step out
    Run,                   // Run program
    Restart,               // Restart program
    Quit,                  // Quit debugger
    
    // Display commands
    Print(String),         // Print expression
    Display(String),       // Display expression each time program stops
    Memory(u64, usize),    // View memory at address with size
    Registers,             // Show registers
    Backtrace,             // Show backtrace
    
    // Trace commands
    TraceOn,               // Enable function call tracing
    TraceOff,              // Disable function call tracing
    TraceClear,            // Clear function call trace
    TraceFilter(String),   // Add a function filter for tracing
    TraceClearFilters,     // Clear all function filters
    
    // Control commands
    Help(Option<String>),  // Show help for command
    Set(String, String),   // Set variable
    Source(String),        // Execute commands from file
    
    // Watchpoint commands
    WatchRead(String),     // Set read watchpoint at address or expression
    WatchWrite(String),    // Set write watchpoint at address or expression
    WatchReadWrite(String), // Set read/write watchpoint at address or expression
    WatchRemove(String),   // Remove watchpoint
    WatchList,             // List all watchpoints
    
    // Unknown command
    Unknown(String),       // Unknown command
}

/// Completion item for command input
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompletionItem {
    pub text: String,
    pub description: String,
    pub kind: CompletionKind,
}

/// Type of completion item
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompletionKind {
    Command,
    Function,
    Variable,
    Address,
    Breakpoint,
}

/// Queued commands for deferred execution
#[derive(Debug)]
#[allow(dead_code)]
pub struct QueuedCommand {
    command: Command,
    timestamp: Instant,
    retries: usize,
}

/// Application state
pub struct App {
    /// The debugger instance
    pub debugger: Arc<Mutex<Debugger>>,
    /// Is the application running?
    pub running: bool,
    /// Current view 
    pub current_view: View,
    /// Currently active/focused UI block
    pub active_block: ActiveBlock,
    /// Current UI mode
    pub ui_mode: UiMode,
    /// Events handler
    events: Events,
    /// Command input text
    pub command_input: String,
    /// Tab that mouse is hovering over
    pub hover_tab: Option<usize>,
    /// Log messages (with rotation)
    pub log_messages: VecDeque<String>,
    /// Log filter level
    pub log_filter: LogFilter,
    /// Custom regex filter for logs
    pub log_filter_regex: Option<Regex>,
    /// Log search text
    pub log_search_text: String,
    /// Log search results (indices into filtered logs)
    pub log_search_results: Vec<usize>,
    /// Current search result index
    pub log_search_index: usize,
    /// Log receiver channel
    log_rx: Option<mpsc::Receiver<String>>,
    /// Is the debugged program running?
    pub program_running: bool,
    /// Number of active breakpoints
    pub breakpoint_count: usize,
    /// List of breakpoints
    pub breakpoints: Vec<Breakpoint>, // Debugger breakpoints
    /// Currently executing function name
    pub current_function: Option<String>,
    /// Process ID of debugged program
    pub process_id: Option<u32>,
    /// Scroll position for log view
    pub log_scroll: usize,
    /// Maximum log buffer size
    max_log_size: usize,
    /// Last UI refresh time
    last_refresh: Instant,
    /// Current mouse position
    pub mouse_position: (u16, u16),
    /// Context menu position
    pub context_menu_position: Option<(u16, u16)>,
    /// Context menu items
    pub context_menu_items: Vec<ContextMenuAction>,
    /// Memory view zoom level
    pub memory_zoom_level: f32,
    /// Tab areas for mouse interaction
    pub tab_areas: Vec<Rect>,
    /// Command history
    pub command_history: VecDeque<String>,
    /// Current history position
    pub command_history_pos: Option<usize>,
    /// Command completion items
    pub completion_items: Vec<CompletionItem>,
    /// Selected completion item
    pub selected_completion: usize,
    /// Command queue for debugger operations
    pub command_queue: VecDeque<QueuedCommand>,
    /// Context menu selection
    pub context_menu_selected: usize,
    /// Documentation for commands
    pub command_docs: HashMap<String, String>,
    /// Memory view data
    pub memory_data: Option<(u64, Vec<u8>)>,
    /// Current memory format for display
    pub memory_format: MemoryFormat,
    /// Current register group tab index (General, Special, SIMD)
    pub register_group_index: usize,
    
    /// Current register selection index within a group
    pub register_selection_index: Option<usize>,
    
    /// Currently displayed registers
    pub registers: Option<Registers>,
    /// Current frame index for stack traces
    pub current_frame: usize,
    /// Command output history
    pub command_output: VecDeque<String>,
    /// Current stack frames
    pub stack_frames: Option<Vec<StackFrame>>,
    /// Current thread list
    pub threads: Option<Vec<(ThreadState, u64)>>,
    /// Last viewed memory
    pub last_memory_view: Option<(u64, Vec<u8>)>,
    /// Is the UI dirty (needs redraw)
    pub dirty: bool,
    /// Was execution just stopped
    pub just_stopped: bool,
    /// Error message to display
    #[allow(dead_code)]
    pub error: Option<String>,
    /// Info message to display
    #[allow(dead_code)]
    pub info: Option<String>,
    /// Status message
    #[allow(dead_code)]
    pub status: String,
    /// Start time of debugging session
    #[allow(dead_code)]
    pub start_time: Instant,
    /// Current breakpoints
    #[allow(dead_code)]
    pub breakpoints_active: Vec<(u64, bool)>,
    /// Expression watch list
    pub watch_expressions: Vec<String>,
    /// Latest expression evaluation result
    pub expression_result: Option<String>,
    /// Performance metrics for frame rendering
    pub frame_times: VecDeque<Duration>,
    /// Maximum number of frame times to keep
    max_frame_times: usize,
    /// Average frame time
    pub avg_frame_time: Duration,
    /// Maximum frame time
    pub max_frame_time: Duration,
    /// Display performance metrics
    pub show_performance: bool,
    /// Current memory view cursor position
    pub memory_cursor: (usize, usize), // (row, column)
    
    /// Memory view selection state (start position if Some)
    pub memory_selection: Option<(usize, usize)>,
    
    /// Memory view scroll offset (row)
    pub memory_scroll: usize,
    
    /// Memory search pattern
    pub memory_search_pattern: Option<SearchPattern>,
    
    /// Memory search results
    pub memory_search_results: Vec<SearchResult>,
    
    /// Current search result index
    pub memory_search_index: usize,
    
    /// Memory search mode (active searching)
    pub memory_search_mode: bool,
    
    /// Memory search input text
    pub memory_search_input: String,
    
    /// Memory currently in edit mode
    pub memory_edit_mode: bool,
    
    /// Memory edit buffer
    pub memory_edit_buffer: String,
    
    /// Memory view status
    pub memory_status: String,
    
    /// Memory view is in address jump mode
    pub memory_jump_mode: bool,
    
    /// Memory jump input
    pub memory_jump_input: String,
    
    /// Memory navigation history (addresses)
    pub memory_history: Vec<u64>,
    
    /// Current position in memory history
    pub memory_history_pos: usize,
}

/// Available views in the application
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum View {
    Code,
    Memory,
    Registers,
    Stack,
    Threads,
    Command,
    Trace,
    Variables,
}

/// Direction enum for memory cursor movement
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CursorDirection {
    Up,
    Down,
    Left,
    Right,
}

impl App {
    /// Create a new application instance
    pub fn new(debugger: Debugger) -> Result<Self> {
        let debugger = Arc::new(Mutex::new(debugger));
        let log_rx = setup_log_capture();
        
        // Initialize log messages with application info
        let mut initial_logs = VecDeque::with_capacity(500);
        let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S%.3f").to_string();
        initial_logs.push_back(format!("[{}] [INFO] RUSTCAT: Debugger initialized", timestamp));
        initial_logs.push_back(format!("[{}] [INFO] RUSTCAT: UI system started", timestamp));
        
        // Initialize command documentation
        let mut command_docs = HashMap::new();
        command_docs.insert("break".to_string(), 
                          "break [location] - Set breakpoint at specified location\n\nExamples:\n  break main\n  break 0x1000\n  break file.c:123".to_string());
        command_docs.insert("continue".to_string(), 
                          "continue - Continue program execution until next breakpoint".to_string());
        command_docs.insert("step".to_string(), 
                          "step - Step into the next instruction or function call".to_string());
        command_docs.insert("next".to_string(), 
                          "next - Step over the next instruction or function call".to_string());
        command_docs.insert("quit".to_string(), 
                          "quit - Exit the debugger".to_string());
        command_docs.insert("print".to_string(),
                          "print [expression] - Evaluate an expression and print the result".to_string());
        command_docs.insert("display".to_string(),
                          "display [expression] - Add an expression to automatically display on each stop".to_string());
        
        Ok(Self {
            debugger,
            running: true,
            current_view: View::Code,
            active_block: ActiveBlock::MainView,
            ui_mode: UiMode::Normal,
            events: Events::new(100),
            command_input: String::new(),
            hover_tab: None,
            log_messages: initial_logs,
            log_filter: LogFilter::Info,
            log_filter_regex: None,
            log_search_text: String::new(),
            log_search_results: Vec::new(),
            log_search_index: 0,
            log_rx: Some(log_rx),
            program_running: false,
            breakpoint_count: 0,
            breakpoints: Vec::new(),
            current_function: Some("main".to_string()),
            process_id: None,
            log_scroll: 0,
            max_log_size: 500,
            last_refresh: Instant::now(),
            mouse_position: (0, 0),
            context_menu_position: None,
            context_menu_items: Vec::new(),
            memory_zoom_level: 1.0,
            tab_areas: Vec::new(),
            command_history: VecDeque::with_capacity(50),
            command_history_pos: None,
            completion_items: Vec::new(),
            selected_completion: 0,
            command_queue: VecDeque::new(),
            context_menu_selected: 0,
            command_docs,
            memory_data: None,
            memory_format: MemoryFormat::Hex,
            register_group_index: 0,
            register_selection_index: None,
            registers: None,
            current_frame: 0,
            command_output: VecDeque::new(),
            stack_frames: None,
            threads: None,
            last_memory_view: None,
            dirty: true,
            just_stopped: false,
            error: None,
            info: None,
            status: String::new(),
            start_time: Instant::now(),
            breakpoints_active: Vec::new(),
            watch_expressions: Vec::new(),
            expression_result: None,
            
            // Initialize performance metrics
            frame_times: VecDeque::with_capacity(100),
            max_frame_times: 100,
            avg_frame_time: Duration::from_micros(0),
            max_frame_time: Duration::from_micros(0),
            show_performance: true,
            
            memory_cursor: (0, 0),
            memory_selection: None,
            memory_scroll: 0,
            memory_search_pattern: None,
            memory_search_results: Vec::new(),
            memory_search_index: 0,
            memory_search_mode: false,
            memory_search_input: String::new(),
            memory_edit_mode: false,
            memory_edit_buffer: String::new(),
            memory_status: String::new(),
            memory_jump_mode: false,
            memory_jump_input: String::new(),
            memory_history: Vec::new(),
            memory_history_pos: 0,
        })
    }

    /// Get filtered log messages based on current level filter
    #[must_use]
    pub fn filtered_logs(&self) -> Vec<&String> {
        let filtered: Vec<&String> = self.log_messages
            .iter()
            .filter(|msg| {
                let base_filter = match self.log_filter {
                    LogFilter::Debug | LogFilter::Custom => true, // Both return true with different handling
                    LogFilter::Info => !msg.contains("[DEBUG]"),
                    LogFilter::Warn => msg.contains("[WARN]") || msg.contains("[ERROR]"),
                    LogFilter::Error => msg.contains("[ERROR]"),
                };
                
                // Apply regex filter if it exists and base filter passes
                if base_filter && self.log_filter == LogFilter::Custom {
                    if let Some(regex) = &self.log_filter_regex {
                        return regex.is_match(msg);
                    }
                }
                
                base_filter
            })
            .collect();
        
        filtered
    }
    
    /// Cycle through log filter levels
    pub const fn cycle_log_filter(&mut self) {
        self.log_filter = match self.log_filter {
            LogFilter::Debug => LogFilter::Info,
            LogFilter::Info => LogFilter::Warn,
            LogFilter::Warn => LogFilter::Error,
            LogFilter::Error => LogFilter::Custom,
            LogFilter::Custom => LogFilter::Debug,
        };
        // Reset scroll position when changing filter
        self.log_scroll = 0;
    }
    
    #[allow(dead_code)]
    pub fn set_log_filter_regex(&mut self, pattern: &str) -> Result<()> {
        match Regex::new(pattern) {
            Ok(regex) => {
                self.log_filter_regex = Some(regex);
                self.log_filter = LogFilter::Custom;
                self.log_scroll = 0;
                Ok(())
            },
            Err(e) => Err(anyhow!("Invalid regex pattern: {}", e)),
        }
    }
    
    #[allow(dead_code)]
    pub fn search_logs(&mut self, search_text: &str) {
        self.log_search_text = search_text.to_string();
        self.log_search_results.clear();
        self.log_search_index = 0;
        
        if search_text.is_empty() {
            return;
        }
        
        // Collect filtered logs into a Vec to avoid borrowing conflicts
        let filtered: Vec<String> = self.filtered_logs().iter().map(|s| (*s).clone()).collect();
        
        // Now search through the collected logs
        for (idx, log) in filtered.iter().enumerate() {
            if log.to_lowercase().contains(&search_text.to_lowercase()) {
                self.log_search_results.push(idx);
            }
        }
    }
    
    /// Navigate to next search result
    pub fn next_search_result(&mut self) {
        // Keep existing log search functionality for log view
        if !self.log_search_results.is_empty() && (self.current_view == View::Command || self.current_view == View::Trace) {
            self.log_search_index = (self.log_search_index + 1) % self.log_search_results.len();
            // Update scroll position to show the current result
            if let Some(&result_idx) = self.log_search_results.get(self.log_search_index) {
                self.log_scroll = result_idx;
            }
        } 
        // Add memory search functionality
        else if !self.memory_search_results.is_empty() && self.current_view == View::Memory {
            self.memory_search_index = (self.memory_search_index + 1) % self.memory_search_results.len();
            let result = &self.memory_search_results[self.memory_search_index];
            
            self.jump_to_memory_address(result.address);
            self.memory_status = format!("Result {}/{}", self.memory_search_index + 1, self.memory_search_results.len());
        }
    }
    
    /// Navigate to previous search result
    pub fn prev_search_result(&mut self) {
        // Keep existing log search functionality for log view
        if !self.log_search_results.is_empty() && (self.current_view == View::Command || self.current_view == View::Trace) {
            self.log_search_index = if self.log_search_index == 0 {
                self.log_search_results.len() - 1
            } else {
                self.log_search_index - 1
            };
            // Update scroll position to show the current result
            if let Some(&result_idx) = self.log_search_results.get(self.log_search_index) {
                self.log_scroll = result_idx;
            }
        }
        // Add memory search functionality 
        else if !self.memory_search_results.is_empty() && self.current_view == View::Memory {
            if self.memory_search_index == 0 {
                self.memory_search_index = self.memory_search_results.len() - 1;
            } else {
                self.memory_search_index -= 1;
            }
            
            let result = &self.memory_search_results[self.memory_search_index];
            
            self.jump_to_memory_address(result.address);
            self.memory_status = format!("Result {}/{}", self.memory_search_index + 1, self.memory_search_results.len());
        }
    }
    
    /// Export logs to a file
    pub fn export_logs(&self, path: &str) -> Result<()> {
        let filtered = self.filtered_logs();
        let mut file = File::create(path).context("Failed to create log file")?;
        
        for log in filtered {
            writeln!(file, "{}", log).context("Failed to write log entry")?;
        }
        
        // Add export timestamp
        let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
        writeln!(file, "\n--- Export completed at {timestamp} ---").context("Failed to write export timestamp")?;
        
        Ok(())
    }
    
    /// Show context menu at current mouse position
    pub fn show_context_menu(&mut self) {
        // Generate context menu items based on current view
        let items = match self.current_view {
            View::Code => {
                vec![
                    ContextMenuAction::SetBreakpoint,
                    ContextMenuAction::RunToCursor,
                    ContextMenuAction::Copy,
                ]
            },
            View::Memory => {
                vec![
                    ContextMenuAction::Copy,
                    ContextMenuAction::SaveToFile,
                ]
            },
            _ => vec![ContextMenuAction::Copy],
        };
        
        self.context_menu_items = items;
        self.context_menu_position = Some(self.mouse_position);
        self.ui_mode = UiMode::ContextMenu;
    }
    
    /// Queue a command for execution
    pub fn queue_command(&mut self, command: Command) {
        debug!("Queuing command: {command:?}");
        let cmd = QueuedCommand {
            command,
            timestamp: Instant::now(),
            retries: 0,
        };
        self.command_queue.push_back(cmd);
    }
    
    /// Process the command queue
    fn process_command_queue(&mut self) -> Result<()> {
        // Skip if no debugger available yet
        if self.debugger.lock().unwrap().get_state() == DebuggerState::Idle {
            return Ok(());
        }
        
        // Get the next command if queue isn't empty
        if self.command_queue.is_empty() {
            return Ok(());
        }
        
        // Pop the command first to avoid borrow checker issues
        let cmd = self.command_queue.pop_front().unwrap().command;
        
        // Lock the debugger only once for the entire command processing
        let mut debugger = self.debugger.lock().unwrap();
        
        match cmd {
            Command::Break(location) => {
                let result = if let Some(s) = location.strip_prefix("0x").or_else(|| location.strip_prefix("0X")) {
                    match u64::from_str_radix(s, 16) {
                        Ok(addr) => debugger.set_hardware_breakpoint(addr),
                        Err(_) => Err(anyhow!("Invalid hex address: {}", location)),
                    }
                } else if location.chars().all(|c| c.is_ascii_digit()) {
                    // Decimal address
                    match location.parse::<u64>() {
                        Ok(addr) => debugger.set_hardware_breakpoint(addr),
                        Err(_) => Err(anyhow!("Invalid address: {}", location)),
                    }
                } else {
                    // Symbol name
                    debugger.set_breakpoint_by_name(&location)
                };
                
                if let Err(e) = result {
                    error!("Failed to set breakpoint: {e}");
                } else {
                    info!("Breakpoint set at {location}");
                }
            },
            Command::Continue => {
                if let Err(e) = debugger.continue_execution() {
                    error!("Failed to continue execution: {e}");
                } else {
                    info!("Continuing execution");
                    self.program_running = true;
                }
            },
            Command::Step => {
                if let Err(e) = debugger.step() {
                    error!("Failed to step: {e}");
                } else {
                    info!("Stepped one instruction");
                }
            },
            Command::Run => {
                if let Err(e) = debugger.run() {
                    error!("Failed to run program: {e}");
                } else {
                    info!("Running program");
                }
            },
            Command::Memory(address, size) => {
                // Read memory
                if let Err(e) = debugger.read_memory(address, size) {
                    error!("Failed to read memory: {e}");
                } else {
                    // Memory data will be updated on next UI redraw
                }
            },
            Command::TraceOn => {
                debugger.enable_function_tracing();
                info!("Function call tracing enabled");
            },
            Command::TraceOff => {
                debugger.disable_function_tracing();
                info!("Function call tracing disabled");
            },
            Command::TraceClear => {
                debugger.clear_function_trace();
                info!("Function call trace cleared");
            },
            Command::TraceFilter(pattern) => {
                debugger.add_function_trace_filter(pattern.clone());
                info!("Added function trace filter: {pattern}");
            },
            Command::TraceClearFilters => {
                debugger.clear_function_trace_filters();
                info!("All function trace filters cleared");
            },
            Command::Print(expression) => {
                match debugger.evaluate_expression(&expression) {
                    Ok(value) => {
                        let result = format!("{} = {}", expression, value);
                        info!("{result}");
                        
                        // Store the result for display in UI
                        drop(debugger); // Release the lock before modifying self
                        self.expression_result = Some(result);
                        
                        // Switch to command view to show the result
                        self.current_view = View::Command;
                    },
                    Err(e) => {
                        error!("Failed to evaluate expression: {e}");
                    }
                }
            },
            Command::Display(expression) => {
                // First, check if the expression can be evaluated
                match debugger.evaluate_expression(&expression) {
                    Ok(_) => {
                        info!("Added watch for: {expression}");
                        
                        // Add to watch list if not already present
                        drop(debugger); // Release the lock before modifying self
                        if !self.watch_expressions.contains(&expression) {
                            self.watch_expressions.push(expression);
                        }
                    },
                    Err(e) => {
                        error!("Cannot watch expression: {e}");
                    }
                }
            },
            Command::WatchRead(expr) => {
                // Drop the lock on debugger to avoid borrow issues
                drop(debugger);
                
                // Try to evaluate the expression to get an address
                let address = self.parse_address_expression(&expr);
                
                if let Some(address) = address {
                    // Re-acquire the lock to set the watchpoint
                    if let Ok(mut debugger) = self.debugger.lock() {
                        if let Err(e) = debugger.set_watchpoint(address, 8, WatchpointType::Read) {
                            error!("Failed to set read watchpoint: {}", e);
                        } else {
                            info!("Set read watchpoint at 0x{:x}", address);
                        }
                    }
                } else {
                    error!("Could not determine address for watchpoint: {}", expr);
                }
            },
            Command::WatchWrite(expr) => {
                // Drop the lock on debugger to avoid borrow issues
                drop(debugger);
                
                // Try to evaluate the expression to get an address
                let address = self.parse_address_expression(&expr);
                
                if let Some(address) = address {
                    // Re-acquire the lock to set the watchpoint
                    if let Ok(mut debugger) = self.debugger.lock() {
                        if let Err(e) = debugger.set_watchpoint(address, 8, WatchpointType::Write) {
                            error!("Failed to set write watchpoint: {}", e);
                        } else {
                            info!("Set write watchpoint at 0x{:x}", address);
                        }
                    }
                } else {
                    error!("Could not determine address for watchpoint: {}", expr);
                }
            },
            Command::WatchReadWrite(expr) => {
                // Drop the lock on debugger to avoid borrow issues
                drop(debugger);
                
                // Try to evaluate the expression to get an address
                let address = self.parse_address_expression(&expr);
                
                if let Some(address) = address {
                    // Re-acquire the lock to set the watchpoint
                    if let Ok(mut debugger) = self.debugger.lock() {
                        if let Err(e) = debugger.set_watchpoint(address, 8, WatchpointType::ReadWrite) {
                            error!("Failed to set read/write watchpoint: {}", e);
                        } else {
                            info!("Set read/write watchpoint at 0x{:x}", address);
                        }
                    }
                } else {
                    error!("Could not determine address for watchpoint: {}", expr);
                }
            },
            Command::WatchRemove(expr) => {
                // Drop the lock on debugger to avoid borrow issues
                drop(debugger);
                
                // Try to evaluate the expression to get an address
                let address_opt = self.parse_address_expression(&expr);
                
                if let Some(address) = address_opt {
                    // Re-acquire the lock to remove the watchpoint
                    if let Ok(mut debugger) = self.debugger.lock() {
                        if let Err(e) = debugger.remove_watchpoint(address) {
                            error!("Failed to remove watchpoint: {}", e);
                        } else {
                            info!("Removed watchpoint at 0x{:x}", address);
                        }
                    }
                } else {
                    error!("Could not determine address for watchpoint: {}", expr);
                }
            },
            Command::WatchList => {
                // List all watchpoints
                let watchpoints = debugger.get_watchpoints();
                if watchpoints.is_empty() {
                    info!("No active watchpoints");
                } else {
                    info!("Active watchpoints:");
                    for (i, wp) in watchpoints.iter().enumerate() {
                        info!("[{}] {}", i, wp);
                    }
                }
            },
            // Handle other commands
            _ => {
                // Unhandled command
                warn!("Unhandled command: {cmd:?}");
            },
        }
        
        Ok(())
    }
    
    /// Parse command text into a Command enum
    #[must_use]
    pub fn parse_command(&self, cmd_str: &str) -> Command {
        let cmd_str = cmd_str.trim();
        if cmd_str.is_empty() {
            return Command::Unknown(String::new());
        }
        
        // Split command into parts
        let parts: Vec<&str> = cmd_str.split_whitespace().collect();
        
        match parts[0] {
            "b" | "break" => {
                if parts.len() > 1 {
                    Command::Break(parts[1].to_string())
                } else {
                    Command::Unknown("break requires an address or function name".to_string())
                }
            },
            "c" | "continue" => Command::Continue,
            "s" | "step" => Command::Step,
            "n" | "next" => Command::Next,
            "fin" | "finish" => Command::Finish,
            "r" | "run" => Command::Run,
            "restart" => Command::Restart,
            "q" | "quit" => Command::Quit,
            "p" | "print" => {
                if parts.len() > 1 {
                    Command::Print(parts[1..].join(" "))
                } else {
                    Command::Unknown("print requires an expression".to_string())
                }
            },
            "display" => {
                if parts.len() > 1 {
                    Command::Display(parts[1..].join(" "))
                } else {
                    Command::Unknown("display requires an expression".to_string())
                }
            },
            "m" | "memory" => {
                if parts.len() >= 3 {
                    // Parse address
                    let addr_str = parts[1];
                    let addr = if let Some(s) = addr_str.strip_prefix("0x").or_else(|| addr_str.strip_prefix("0X")) {
                        match u64::from_str_radix(s, 16) {
                            Ok(addr) => addr,
                            Err(_) => return Command::Unknown(format!("Invalid hex address: {addr_str}")),
                        }
                    } else {
                        match addr_str.parse::<u64>() {
                            Ok(addr) => addr,
                            Err(_) => return Command::Unknown(format!("Invalid address: {addr_str}")),
                        }
                    };
                    
                    // Parse the size
                    let size_str = parts[2];
                    let size = match size_str.parse::<usize>() {
                        Ok(size) => size,
                        Err(_) => return Command::Unknown(format!("Invalid size: {size_str}")),
                    };
                    
                    Command::Memory(addr, size)
                } else {
                    // Default to breaking at "main" if no location specified
                    Command::Break("main".to_string())
                }
            },
            "regs" | "registers" => Command::Registers,
            "bt" | "backtrace" => Command::Backtrace,
            "h" | "help" => {
                if parts.len() > 1 {
                    Command::Help(Some(parts[1].to_string()))
                } else {
                    Command::Help(None)
                }
            },
            "set" => {
                if parts.len() >= 3 {
                    Command::Set(parts[1].to_string(), parts[2..].join(" "))
                } else {
                    Command::Unknown("set requires a variable name and value".to_string())
                }
            },
            "source" => {
                if parts.len() > 1 {
                    Command::Source(parts[1].to_string())
                } else {
                    Command::Unknown("source requires a filename".to_string())
                }
            },
            "traceon" => Command::TraceOn,
            "traceoff" => Command::TraceOff,
            "traceclear" => Command::TraceClear,
            "tracefilter" => {
                if parts.len() > 1 {
                    Command::TraceFilter(parts[1].to_string())
                } else {
                    Command::Unknown("tracefilter requires a function name".to_string())
                }
            },
            "traceclearfilters" => Command::TraceClearFilters,
            "watch" => {
                if parts.len() > 1 {
                    Command::WatchReadWrite(parts[1..].join(" "))
                } else {
                    Command::Unknown("watch requires an address or expression".to_string())
                }
            },
            "rwatch" => {
                if parts.len() > 1 {
                    Command::WatchRead(parts[1..].join(" "))
                } else {
                    Command::Unknown("rwatch requires an address or expression".to_string())
                }
            },
            "awatch" => {
                if parts.len() > 1 {
                    Command::WatchReadWrite(parts[1..].join(" "))
                } else {
                    Command::Unknown("awatch requires an address or expression".to_string())
                }
            },
            "wwatch" => {
                if parts.len() > 1 {
                    Command::WatchWrite(parts[1..].join(" "))
                } else {
                    Command::Unknown("wwatch requires an address or expression".to_string())
                }
            },
            "unwatch" => {
                if parts.len() > 1 {
                    Command::WatchRemove(parts[1..].join(" "))
                } else {
                    Command::Unknown("unwatch requires an address or watchpoint ID".to_string())
                }
            },
            "watchlist" => Command::WatchList,
            _ => Command::Unknown(cmd_str.to_string()),
        }
    }
    
    #[allow(dead_code)]
    pub fn get_completions(&self, input: &str) -> Vec<CompletionItem> {
        let mut completions = Vec::new();
        
        // Basic commands
        let commands = vec![
            ("break", "Set breakpoint"),
            ("continue", "Continue execution"),
            ("step", "Step into"),
            ("next", "Step over"),
            ("finish", "Step out"),
            ("run", "Run program"),
            ("quit", "Quit debugger"),
            ("print", "Print expression"),
            ("help", "Show help"),
            ("watch", "Set read/write watchpoint"),
            ("rwatch", "Set read watchpoint"),
            ("wwatch", "Set write watchpoint"),
            ("awatch", "Set read/write watchpoint (same as watch)"),
            ("unwatch", "Remove watchpoint"),
            ("watchlist", "List all watchpoints"),
        ];
        
        // Filter commands by input prefix
        for (cmd, desc) in commands {
            if cmd.starts_with(input) {
                completions.push(CompletionItem {
                    text: cmd.to_string(),
                    description: desc.to_string(),
                    kind: CompletionKind::Command,
                });
            }
        }
        
        // If input starts with "break ", suggest functions
        if input.starts_with("break ") || input.starts_with("b ") {
            if let Ok(_debugger) = self.debugger.try_lock() {
                // Placeholder until properly implemented
                // for func in debugger.get_functions() {
                let functions = vec![
                    CompletionItem {
                        text: "break main".to_string(),
                        description: "Set breakpoint at main function".to_string(),
                        kind: CompletionKind::Function
                    }
                ];
                
                for func in functions {
                    if input.find(' ').is_some_and(|pos| func.text.contains(&input[pos + 1..])) {
                        completions.push(func);
                    }
                }
            }
        }
        
        // Add memory address completions for the memory view
        if input.starts_with("x/") && self.current_view == View::Memory {
            if let Ok(_debugger) = self.debugger.try_lock() {
                // Placeholder until get_memory_addresses is implemented
                let addresses = vec![0x1000u64, 0x2000u64];
                for addr in addresses {
                    let addr_str = format!("0x{:x}", addr);
                    completions.push(CompletionItem {
                        text: format!("x/{}", addr_str),
                        description: format!("Examine memory at {}", addr_str),
                        kind: CompletionKind::Address,
                    });
                }
            }
        }
        
        completions
    }
    /// Update the app state from the debugger
    #[allow(dead_code)]
    fn update_debugger_state(&mut self, debugger: &Debugger) {
        // Update current function - placeholder until current_function_name is implemented
        self.current_function = Some("main".to_string());
        
        // Update program state - placeholder until is_running is implemented
        self.program_running = false;
        
        // Update process ID - placeholder until process_id is implemented
        self.process_id = None;
        
        // Update breakpoints - manually clone the breakpoints from the slice
        self.breakpoints = debugger.get_breakpoints().to_vec();
        self.breakpoint_count = self.breakpoints.len();
    }
    
    /// Process any new log messages
    fn process_log_messages(&mut self) {
        if let Some(rx) = &self.log_rx {
            // Process all available log messages
            loop {
                match rx.try_recv() {
                    Ok(message) => {
                        self.log_messages.push_back(message);
                        // Enforce maximum log size with rotation
                        if self.log_messages.len() > self.max_log_size {
                            self.log_messages.pop_front();
                        }
                    }
                    Err(std::sync::mpsc::TryRecvError::Empty) => break,
                    Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                        self.log_rx = None;
                        break;
                    }
                }
            }
        }
    }
    
    /// Run the application
    pub fn run(&mut self) -> Result<()> {
        // Terminal initialization
        enable_raw_mode()?;
        let mut stdout = std::io::stdout();
        execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
        
        // Create terminal
        let backend = CrosstermBackend::new(stdout);
        let mut terminal = Terminal::new(backend)?;
        
        // Main event loop
        while self.running {
            // Update debugger state by temporarily cloning necessary data
            {
                let debugger_lock = self.debugger.lock().unwrap();
                // Clone any data we need from the debugger to update state
                let current_function = Some("main".to_string()); // Example
                let breakpoints = debugger_lock.get_breakpoints().to_vec();
                // Drop lock before updating self
                drop(debugger_lock);
                
                // Now update self with the cloned data
                self.current_function = current_function;
                self.breakpoints = breakpoints;
                self.breakpoint_count = self.breakpoints.len();
            }
            
            // Process log messages
            self.process_log_messages();
            
            // Process command queue
            if let Err(e) = self.process_command_queue() {
                error!("Error processing command: {}", e);
            }
            
            // Start measuring frame rendering time
            let frame_start = Instant::now();
            
            // Draw the UI
            terminal.draw(|f| draw_ui(f, self))?;
            
            // Calculate frame time and update metrics
            let frame_time = frame_start.elapsed();
            self.frame_times.push_back(frame_time);
            if self.frame_times.len() > self.max_frame_times {
                self.frame_times.pop_front();
            }
            
            // Update average frame time
            if !self.frame_times.is_empty() {
                let total_time: Duration = self.frame_times.iter().sum();
                self.avg_frame_time = total_time / self.frame_times.len() as u32;
                self.max_frame_time = *self.frame_times.iter().max().unwrap_or(&Duration::from_micros(0));
            }
            
            // Check if any UI frames are taking longer than 10ms
            if frame_time > Duration::from_millis(10) {
                warn!("Slow UI frame: {:?}", frame_time);
            }
            
            // Poll for events
            if let Ok(event) = self.events.next() {
                if let Err(e) = self.handle_input(event) {
                    error!("Error handling input: {}", e);
                }
            }
        }
        
        // Terminal cleanup
        disable_raw_mode()?;
        execute!(
            terminal.backend_mut(),
            DisableMouseCapture,
            crossterm::terminal::LeaveAlternateScreen
        )?;
        
        terminal.show_cursor()?;
        
        Ok(())
    }

    /// Handle input events
    fn handle_input(&mut self, event: Event) -> Result<()> {
        match event {
            Event::Key(key) => {
                // Global key handler regardless of active block
                match key.code {
                    // Quit - Global
                    KeyCode::Char('q') if key.modifiers.is_empty() => {
                        self.running = false;
                        return Ok(());
                    },
                    // Tab between UI sections
                    KeyCode::Tab => {
                        self.active_block = match self.active_block {
                            ActiveBlock::MainView => ActiveBlock::CommandInput,
                            ActiveBlock::CommandInput => ActiveBlock::LogView,
                            ActiveBlock::LogView => ActiveBlock::MainView,
                        };
                        return Ok(());
                    },
                    _ => {}
                }
                
                // Active block specific handlers
                match self.active_block {
                    ActiveBlock::MainView => {
                        match key.code {
                            // Change view with number keys
                            KeyCode::Char('1') => self.current_view = View::Code,
                            KeyCode::Char('2') => self.current_view = View::Memory,
                            KeyCode::Char('3') => self.current_view = View::Registers,
                            KeyCode::Char('4') => self.current_view = View::Stack,
                            KeyCode::Char('5') => self.current_view = View::Threads,
                            KeyCode::Char('6') => self.current_view = View::Trace,
                            KeyCode::Char('7') => self.current_view = View::Variables,
                            KeyCode::Char('8') => self.current_view = View::Command,
                            
                            // Legacy view keys
                            KeyCode::Char('c') => self.current_view = View::Code,
                            KeyCode::Char('m') => self.current_view = View::Memory,
                            KeyCode::Char('r') => self.current_view = View::Registers,
                            // 's' key is also used for stepping, so use a modifier key instead
                            KeyCode::Char('w') => self.current_view = View::Stack, // Using 'w' for 'Stack'
                            KeyCode::Char('t') => self.current_view = View::Threads,
                            KeyCode::Char('f') => self.current_view = View::Trace, // Using 'f' for function tracer
                            KeyCode::Char('v') => self.current_view = View::Variables, // Using 'v' for Variables
                            
                            // Toggle help overlay with F1
                            KeyCode::F(1) => {
                                self.ui_mode = if self.ui_mode == UiMode::HelpOverlay {
                                    UiMode::Normal
                                } else {
                                    UiMode::HelpOverlay
                                };
                                debug!("Help overlay: {}", if self.ui_mode == UiMode::HelpOverlay { "shown" } else { "hidden" });
                            },
                            
                            // Toggle performance metrics display with F3
                            KeyCode::F(3) => {
                                self.toggle_performance_metrics();
                                debug!("Performance metrics display: {}", if self.show_performance { "on" } else { "off" });
                            },
                            
                            // Focus command input
                            KeyCode::Char(':') => {
                                self.current_view = View::Command;
                                self.active_block = ActiveBlock::CommandInput;
                            },
                            
                            // Debugger commands
                            KeyCode::Char('g') => {
                                self.program_running = true;
                                let mut debugger = self.debugger.lock().unwrap();
                                debugger.run()?;
                            },
                            KeyCode::Char('b') => {
                                // Toggle breakpoint at current line
                                self.breakpoint_count += 1;
                            },
                            KeyCode::Char('n') => {
                                // Step over instruction
                                self.queue_command(Command::Next);
                            },
                            KeyCode::Char('i') => {
                                // Step into instruction
                                self.queue_command(Command::Step);
                            },
                            _ => {},
                        }
                    },
                    
                    ActiveBlock::CommandInput => {
                        match key.code {
                            KeyCode::Up => {
                                if let Some(pos) = self.command_history_pos {
                                    if pos > 0 {
                                        self.command_history_pos = Some(pos - 1);
                                        self.command_input = self.command_history[pos - 1].clone();
                                    }
                                } else if !self.command_history.is_empty() {
                                    self.command_history_pos = Some(self.command_history.len() - 1);
                                    self.command_input = self.command_history[self.command_history.len() - 1].clone();
                                }
                            },
                            KeyCode::Down => {
                                if let Some(pos) = self.command_history_pos {
                                    if pos < self.command_history.len() - 1 {
                                        self.command_history_pos = Some(pos + 1);
                                        self.command_input = self.command_history[pos + 1].clone();
                                    } else {
                                        self.command_history_pos = None;
                                        self.command_input.clear();
                                    }
                                }
                            },
                            KeyCode::Esc => {
                                self.active_block = ActiveBlock::MainView;
                            },
                            KeyCode::Enter => {
                                if !self.command_input.is_empty() {
                                    // Parse and queue command
                                    let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
                                    self.log_messages.push_back(format!("[{}] [CMD] {}", timestamp, self.command_input));
                                    
                                    let cmd = self.parse_command(&self.command_input);
                                    self.queue_command(cmd);
                                    
                                    // Add to history if not already present
                                    if !self.command_history.contains(&self.command_input) {
                                        if self.command_history.len() >= 50 {
                                            self.command_history.pop_front();
                                        }
                                        self.command_history.push_back(self.command_input.clone());
                                    }
                                    self.command_history_pos = None;
                                    
                                    self.command_input.clear();
                                }
                                self.active_block = ActiveBlock::MainView;
                            },
                            KeyCode::Char(c) => {
                                self.command_input.push(c);
                            },
                            KeyCode::Backspace => {
                                self.command_input.pop();
                            },
                            _ => {},
                        }
                    },
                    
                    ActiveBlock::LogView => {
                        match key.code {
                            KeyCode::Up => {
                                if self.log_scroll > 0 {
                                    self.log_scroll -= 1;
                                }
                            },
                            KeyCode::Down => {
                                let max_scroll = self.filtered_logs().len().saturating_sub(1);
                                if self.log_scroll < max_scroll {
                                    self.log_scroll += 1;
                                }
                            },
                            KeyCode::PageUp => {
                                self.log_scroll = self.log_scroll.saturating_sub(10);
                            },
                            KeyCode::PageDown => {
                                let max_scroll = self.filtered_logs().len().saturating_sub(1);
                                self.log_scroll = (self.log_scroll + 10).min(max_scroll);
                            },
                            KeyCode::Home => {
                                self.log_scroll = 0;
                            },
                            KeyCode::End => {
                                let max_scroll = self.filtered_logs().len().saturating_sub(1);
                                self.log_scroll = max_scroll;
                            },
                            KeyCode::Char('f') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                                self.ui_mode = UiMode::LogSearch;
                                self.command_input.clear(); // Reuse command input for search
                                self.active_block = ActiveBlock::CommandInput;
                            },
                            KeyCode::Char('n') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                                self.next_search_result();
                            },
                            KeyCode::Char('p') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                                self.prev_search_result();
                            },
                            KeyCode::Char('e') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                                // Export logs with timestamp in filename
                                let timestamp = chrono::Local::now().format("%Y%m%d_%H%M%S").to_string();
                                let filename = format!("rustcat_logs_{}.log", timestamp);
                                
                                if let Err(e) = self.export_logs(&filename) {
                                    let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
                                    self.log_messages.push_back(format!("[{}] [ERROR] Error exporting logs: {}", timestamp, e));
                                } else {
                                    let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
                                    self.log_messages.push_back(format!("[{}] [INFO] Logs exported to {}", timestamp, filename));
                                }
                            },
                            KeyCode::Char('l') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                                // Cycle log filter
                                self.cycle_log_filter();
                            },
                            _ => {},
                        }
                    },
                }
            },
            
            Event::Mouse(mouse) => {
                self.mouse_position = (mouse.column, mouse.row);
                
                // Handle different mouse modes
                match self.ui_mode {
                    UiMode::ContextMenu => {
                        if let MouseEventKind::Down(MouseButton::Left) = mouse.kind {
                            // Handle context menu selection
                            // We would select menu item based on position
                            self.ui_mode = UiMode::Normal;
                            self.context_menu_position = None;
                        } else if let MouseEventKind::Down(MouseButton::Right) = mouse.kind {
                            // Right click again to dismiss
                            self.ui_mode = UiMode::Normal;
                            self.context_menu_position = None;
                        }
                    },
                    _ => {
                        match mouse.kind {
                            MouseEventKind::Down(MouseButton::Left) => {
                                // Check if click is in tab area
                                for (idx, area) in self.tab_areas.iter().enumerate() {
                                    // Check if point is within rectangle bounds
                                    if self.mouse_position.0 >= area.x && 
                                       self.mouse_position.0 < area.x + area.width &&
                                       self.mouse_position.1 >= area.y && 
                                       self.mouse_position.1 < area.y + area.height {
                                        self.current_view = match idx {
                                            0 => View::Code,
                                            1 => View::Memory,
                                            2 => View::Registers,
                                            3 => View::Stack,
                                            4 => View::Threads,
                                            5 => View::Command,
                                            6 => View::Variables,
                                            _ => self.current_view,
                                        };
                                        break;
                                    }
                                }
                            },
                            MouseEventKind::Down(MouseButton::Right) => {
                                self.show_context_menu();
                            },
                            MouseEventKind::ScrollDown => {
                                if self.active_block == ActiveBlock::LogView {
                                    let max_scroll = self.filtered_logs().len().saturating_sub(1);
                                    if self.log_scroll < max_scroll {
                                        self.log_scroll += 1;
                                    }
                                } else if self.current_view == View::Memory {
                                    // Zoom out memory view
                                    self.memory_zoom_level = (self.memory_zoom_level - 0.1).max(0.5);
                                }
                            },
                            MouseEventKind::ScrollUp => {
                                if self.active_block == ActiveBlock::LogView && self.log_scroll > 0 {
                                    self.log_scroll -= 1;
                                } else if self.current_view == View::Memory {
                                    // Zoom in memory view
                                    self.memory_zoom_level = (self.memory_zoom_level + 0.1).min(2.0);
                                }
                            },
                            _ => {},
                        }
                    }
                }
            },
            
            // Other event types
            _ => {},
        }
        
        Ok(())
    }

    /// Get memory data for display
    pub fn get_memory_data(&self) -> Option<(u64, &Vec<u8>)> {
        self.memory_data.as_ref().map(|(addr, data)| (*addr, data))
    }
    
    /// Set memory data for display
    pub fn set_memory_data(&mut self, address: u64, data: Vec<u8>) {
        self.memory_data = Some((address, data));
    }
    
    /// Get current memory format
    pub fn get_memory_format(&self) -> MemoryFormat {
        self.memory_format
    }
    
    /// Set memory format
    #[allow(dead_code)]
    pub fn set_memory_format(&mut self, format: MemoryFormat) {
        self.memory_format = format;
    }
    
    /// Cycle through memory formats
    #[allow(dead_code)]
    pub fn cycle_memory_format(&mut self) {
        self.memory_format = match self.memory_format {
            MemoryFormat::Hex => MemoryFormat::Ascii,
            MemoryFormat::Ascii => MemoryFormat::Utf8,
            MemoryFormat::Utf8 => MemoryFormat::U32,
            MemoryFormat::U32 => MemoryFormat::I32,
            MemoryFormat::I32 => MemoryFormat::F32,
            MemoryFormat::F32 => MemoryFormat::Hex,
            _ => MemoryFormat::Hex,
        };
    }

    /// Get reference to the debugger
    pub fn get_debugger(&self) -> &Arc<Mutex<Debugger>> {
        &self.debugger
    }

    /// Get the current register values
    pub fn get_registers(&self) -> Option<&Registers> {
        self.registers.as_ref()
    }
    
    /// Update register values
    pub fn update_registers(&mut self, _registers: Registers) {
        self.registers = Some(_registers);
    }
    
    /// Select the next register group
    #[allow(dead_code)]
    pub fn next_register_group(&mut self) {
        self.register_group_index = (self.register_group_index + 1) % 3; // 3 groups
        self.register_selection_index = None; // Reset selection
    }
    
    /// Select the previous register group
    #[allow(dead_code)]
    pub fn previous_register_group(&mut self) {
        self.register_group_index = (self.register_group_index + 2) % 3; // 3 groups
        self.register_selection_index = None; // Reset selection
    }
    
    /// Select the next register in the current group
    #[allow(dead_code)]
    pub fn next_register(&mut self) {
        if let Some(_registers) = &self.registers {
            let group_len = match self.register_group_index {
                0 => 31, // General purpose (X0-X30)
                1 => 3,  // Special (SP, PC, CPSR)
                2 => 32, // SIMD (Q0-Q31)
                _ => 0,
            };
            
            if group_len > 0 {
                let idx = self.register_selection_index.unwrap_or_default();
                self.register_selection_index = Some((idx + 1) % group_len);
            }
        }
    }
    
    /// Select the previous register in the current group
    #[allow(dead_code)]
    pub fn previous_register(&mut self) {
        if let Some(_registers) = &self.registers {
            let group_len = match self.register_group_index {
                0 => 31, // General purpose (X0-X30)
                1 => 3,  // Special (SP, PC, CPSR)
                2 => 32, // SIMD (Q0-Q31)
                _ => 0,
            };
            
            if group_len > 0 {
                let idx = self.register_selection_index.unwrap_or_default();
                self.register_selection_index = Some((idx + group_len - 1) % group_len);
            }
        }
    }

    /// Update variable values
    pub fn update_variables(&mut self) {
        if let Ok(debugger) = self.debugger.lock() {
            // Fetch real variables from the debugger core for the current frame
            let frame_index = self.current_frame;
            let variables = debugger.get_variables_by_frame(frame_index);
            // Here, you would update the app's variable display state with these variables
            // For now, we just log them to ensure the types are used
            for var in variables {
                debug!("Variable: {}: {} = {} (scope: {})", var.name(), var.var_type(), var.value(), var.scope());
            }
        }
    }

    // Add a helper method to parse addresses for watchpoints
    fn parse_address_expression(&self, expr: &str) -> Option<u64> {
        // Try to evaluate as an expression first
        if let Ok(mut debugger) = self.debugger.lock() {
            if let Ok(value) = debugger.evaluate_expression(expr) {
                match value {
                    crate::debugger::variables::VariableValue::Integer(address) => return Some(address as u64),
                    crate::debugger::variables::VariableValue::UnsignedInteger(address) => return Some(address),
                    crate::debugger::variables::VariableValue::Address(address) => return Some(address),
                    _ => {}
                }
            }
        }
        
        // Try to parse as a hex or decimal address
        if let Some(s) = expr.strip_prefix("0x").or_else(|| expr.strip_prefix("0X")) {
            u64::from_str_radix(s, 16).ok()
        } else {
            expr.parse::<u64>().ok()
        }
    }

    /// Toggle performance metrics display
    pub fn toggle_performance_metrics(&mut self) {
        self.show_performance = !self.show_performance;
    }
    
    /// Get current performance metrics
    pub fn get_performance_metrics(&self) -> (Duration, Duration, bool) {
        (self.avg_frame_time, self.max_frame_time, self.avg_frame_time > Duration::from_millis(10))
    }

    /// Move memory cursor
    pub fn move_memory_cursor(&mut self, direction: CursorDirection, data_len: usize, bytes_per_row: usize) {
        if data_len == 0 {
            return;
        }
        
        let (row, col) = self.memory_cursor;
        let rows = (data_len + bytes_per_row - 1) / bytes_per_row;
        
        let new_pos = match direction {
            CursorDirection::Up => {
                if row > 0 {
                    (row - 1, col)
                } else {
                    (row, col)
                }
            },
            CursorDirection::Down => {
                if row < rows - 1 {
                    (row + 1, col)
                } else {
                    (row, col)
                }
            },
            CursorDirection::Left => {
                if col > 0 {
                    (row, col - 1)
                } else if row > 0 {
                    (row - 1, bytes_per_row - 1) // Wrap to end of previous row
                } else {
                    (row, col)
                }
            },
            CursorDirection::Right => {
                let last_row_len = if row == rows - 1 {
                    data_len % bytes_per_row
                } else {
                    bytes_per_row
                };
                
                if col < last_row_len - 1 {
                    (row, col + 1)
                } else if row < rows - 1 {
                    (row + 1, 0) // Wrap to start of next row
                } else {
                    (row, col)
                }
            },
        };
        
        self.memory_cursor = new_pos;
        
        // Ensure cursor is visible by adjusting scroll if needed
        let visible_rows = 20; // Approximate number of visible rows
        if self.memory_cursor.0 < self.memory_scroll {
            self.memory_scroll = self.memory_cursor.0;
        } else if self.memory_cursor.0 >= self.memory_scroll + visible_rows {
            self.memory_scroll = self.memory_cursor.0 - visible_rows + 1;
        }
    }
    
    /// Get the absolute offset for current memory cursor
    pub fn get_memory_cursor_offset(&self, bytes_per_row: usize) -> usize {
        let (row, col) = self.memory_cursor;
        (row * bytes_per_row) + col
    }
    
    /// Get the address for current memory cursor
    pub fn get_memory_cursor_address(&self, base_address: u64, bytes_per_row: usize) -> u64 {
        let offset = self.get_memory_cursor_offset(bytes_per_row);
        base_address + offset as u64
    }
    
    /// Start memory selection from cursor
    pub fn start_memory_selection(&mut self) {
        self.memory_selection = Some(self.memory_cursor);
    }
    
    /// End memory selection and return selected range
    pub fn end_memory_selection(&mut self, bytes_per_row: usize) -> Option<(usize, usize)> {
        if let Some(start_pos) = self.memory_selection {
            let end_pos = self.memory_cursor;
            
            // Convert 2D positions to flat offsets
            let start_offset = start_pos.0 * bytes_per_row + start_pos.1;
            let end_offset = end_pos.0 * bytes_per_row + end_pos.1;
            
            let range = if start_offset <= end_offset {
                (start_offset, end_offset + 1)
            } else {
                (end_offset, start_offset + 1)
            };
            
            self.memory_selection = None;
            Some(range)
        } else {
            None
        }
    }
    
    /// Reset memory selection
    pub fn reset_memory_selection(&mut self) {
        self.memory_selection = None;
    }
    
    /// Check if a position is within the current selection range
    pub fn is_position_selected(&self, row: usize, col: usize, bytes_per_row: usize) -> bool {
        if let Some(start_pos) = self.memory_selection {
            let current_pos = self.memory_cursor;
            
            // Convert 2D positions to flat offsets
            let start_offset = start_pos.0 * bytes_per_row + start_pos.1;
            let end_offset = current_pos.0 * bytes_per_row + current_pos.1;
            let pos_offset = row * bytes_per_row + col;
            
            if start_offset <= end_offset {
                pos_offset >= start_offset && pos_offset <= end_offset
            } else {
                pos_offset >= end_offset && pos_offset <= start_offset
            }
        } else {
            false
        }
    }
    
    /// Jump to memory address
    pub fn jump_to_memory_address(&mut self, address: u64) {
        if let Some((base_addr, data)) = &self.memory_data {
            if address >= *base_addr && address < *base_addr + data.len() as u64 {
                // Address is in current range, move cursor
                let offset = (address - *base_addr) as usize;
                let bytes_per_row = 16; // Standard bytes per row
                let row = offset / bytes_per_row;
                let col = offset % bytes_per_row;
                
                self.memory_cursor = (row, col);
                
                // Also update scroll
                let visible_rows = 20; // Approximate
                if row < self.memory_scroll || row >= self.memory_scroll + visible_rows {
                    self.memory_scroll = row.saturating_sub(5); // Position with some context
                }
                
                // Add to history if it's a new address
                self.add_to_memory_history(address);
            } else {
                // Need to request new memory region
                self.memory_status = format!("Loading memory at 0x{:x}...", address);
                
                // Add to history
                self.add_to_memory_history(address);
                
                // This would be followed by a memory read operation elsewhere,
                // which happens asynchronously
            }
        } else {
            // No memory loaded yet, just record the navigation intent
            self.memory_status = format!("No memory data loaded. Request memory at 0x{:x} first.", address);
        }
    }
    
    /// Add address to memory navigation history
    fn add_to_memory_history(&mut self, address: u64) {
        // Don't add duplicates
        if self.memory_history.last() == Some(&address) {
            return;
        }
        
        // If we're not at the end of history, truncate
        if self.memory_history_pos < self.memory_history.len() - 1 {
            self.memory_history.truncate(self.memory_history_pos + 1);
        }
        
        // Add the new address
        self.memory_history.push(address);
        self.memory_history_pos = self.memory_history.len() - 1;
        
        // Cap history size
        const MAX_HISTORY_SIZE: usize = 100;
        if self.memory_history.len() > MAX_HISTORY_SIZE {
            self.memory_history.remove(0);
            self.memory_history_pos = self.memory_history.len() - 1;
        }
    }
    
    /// Navigate back in memory history
    pub fn memory_history_back(&mut self) -> Option<u64> {
        if self.memory_history_pos > 0 {
            self.memory_history_pos -= 1;
            Some(self.memory_history[self.memory_history_pos])
        } else {
            None
        }
    }
    
    /// Navigate forward in memory history
    pub fn memory_history_forward(&mut self) -> Option<u64> {
        if self.memory_history_pos < self.memory_history.len() - 1 {
            self.memory_history_pos += 1;
            Some(self.memory_history[self.memory_history_pos])
        } else {
            None
        }
    }
    
    /// Start memory search
    pub fn start_memory_search(&mut self) {
        self.memory_search_mode = true;
        self.memory_search_input.clear();
        self.memory_status = "Search: ".to_string();
    }
    
    /// Cancel memory search
    pub fn cancel_memory_search(&mut self) {
        self.memory_search_mode = false;
        self.memory_search_input.clear();
        self.memory_status = "Search canceled".to_string();
    }
    
    /// Start memory edit mode
    pub fn start_memory_edit(&mut self) {
        self.memory_edit_mode = true;
        self.memory_edit_buffer.clear();
        self.memory_status = "Edit mode: Enter hex value".to_string();
    }
    
    /// Cancel memory edit mode
    pub fn cancel_memory_edit(&mut self) {
        self.memory_edit_mode = false;
        self.memory_edit_buffer.clear();
        self.memory_status = "Edit canceled".to_string();
    }
    
    /// Start memory address jump mode
    pub fn start_memory_jump(&mut self) {
        self.memory_jump_mode = true;
        self.memory_jump_input.clear();
        self.memory_status = "Jump to address: 0x".to_string();
    }
    
    /// Cancel memory jump mode
    pub fn cancel_memory_jump(&mut self) {
        self.memory_jump_mode = false;
        self.memory_jump_input.clear();
        self.memory_status = "Jump canceled".to_string();
    }
    
    /// Execute memory search with current input
    pub fn execute_memory_search(&mut self) -> Result<()> {
        let input = self.memory_search_input.trim();
        if input.is_empty() {
            self.memory_search_mode = false;
            self.memory_status = "Search canceled - empty query".to_string();
            return Ok(());
        }
        
        let pattern = if input.starts_with("0x") || input.starts_with("0X") {
            // Hex bytes search
            match hex::decode(&input[2..]) {
                Ok(bytes) => SearchPattern::Bytes(bytes),
                Err(_) => {
                    self.memory_status = "Invalid hex format".to_string();
                    return Err(anyhow!("Invalid hex format"));
                }
            }
        } else if input.starts_with('"') && input.ends_with('"') {
            // Quoted text search
            let text = &input[1..input.len() - 1];
            SearchPattern::Text(text.to_string())
        } else if input.starts_with('i') && input.contains(':') {
            // Integer search
            let parts: Vec<&str> = input.split(':').collect();
            if parts.len() != 2 {
                self.memory_status = "Invalid integer format. Use i8:123, i16:0xff, etc.".to_string();
                return Err(anyhow!("Invalid integer format"));
            }
            
            let type_str = parts[0];
            let value_str = parts[1];
            
            let width = match type_str {
                "i8" | "u8" => 1,
                "i16" | "u16" => 2,
                "i32" | "u32" => 4,
                "i64" | "u64" => 8,
                _ => {
                    self.memory_status = "Invalid integer type. Use i8, u8, i16, u16, etc.".to_string();
                    return Err(anyhow!("Invalid integer type"));
                }
            };
            
            let value = if value_str.starts_with("0x") {
                // Parse hex
                match u64::from_str_radix(&value_str[2..], 16) {
                    Ok(v) => v,
                    Err(_) => {
                        self.memory_status = "Invalid hex integer value".to_string();
                        return Err(anyhow!("Invalid hex integer value"));
                    }
                }
            } else {
                // Parse decimal
                match value_str.parse::<u64>() {
                    Ok(v) => v,
                    Err(_) => {
                        self.memory_status = "Invalid integer value".to_string();
                        return Err(anyhow!("Invalid integer value"));
                    }
                }
            };
            
            SearchPattern::Integer(value, width)
        } else if input.starts_with('f') && input.contains(':') {
            // Float search
            let parts: Vec<&str> = input.split(':').collect();
            if parts.len() != 2 {
                self.memory_status = "Invalid float format. Use f32:123.45, f64:123.45, etc.".to_string();
                return Err(anyhow!("Invalid float format"));
            }
            
            let type_str = parts[0];
            let value_str = parts[1];
            
            let width = match type_str {
                "f32" => 4,
                "f64" => 8,
                _ => {
                    self.memory_status = "Invalid float type. Use f32 or f64.".to_string();
                    return Err(anyhow!("Invalid float type"));
                }
            };
            
            let value = match value_str.parse::<f64>() {
                Ok(v) => v,
                Err(_) => {
                    self.memory_status = "Invalid float value".to_string();
                    return Err(anyhow!("Invalid float value"));
                }
            };
            
            SearchPattern::Float(value, width)
        } else {
            // Default to case-insensitive text search
            SearchPattern::TextIgnoreCase(input.to_string())
        };
        
        // Perform the search
        let results = {
            if let Some((base_addr, data)) = &self.memory_data {
                // Clone data to avoid borrowing issues
                let data_clone = data.clone();
                let base_addr_clone = *base_addr;
                
                // Get debugger and memory map
                let debugger = self.debugger.lock().unwrap();
                if let Some(mem_map) = debugger.get_memory_map() {
                    Some(mem_map.search_memory(&data_clone, base_addr_clone, &pattern))
                } else {
                    None
                }
            } else {
                None
            }
        };
        
        // Process search results
        if let Some(search_results) = results {
            if search_results.is_empty() {
                self.memory_status = "No matches found".to_string();
            } else {
                self.memory_search_results = search_results;
                self.memory_search_index = 0;
                self.memory_status = format!("Found {} matches", self.memory_search_results.len());
                
                // Jump to first result
                if let Some(result) = self.memory_search_results.first() {
                    self.jump_to_memory_address(result.address);
                }
            }
        } else {
            self.memory_status = "Memory map not available or no memory data loaded".to_string();
        }
        
        self.memory_search_mode = false;
        self.memory_search_pattern = Some(pattern);
        
        Ok(())
    }
    
    /// Execute memory edit with current buffer
    pub fn execute_memory_edit(&mut self) -> Result<()> {
        let input = self.memory_edit_buffer.trim();
        if input.is_empty() {
            self.memory_edit_mode = false;
            self.memory_status = "Edit canceled - empty input".to_string();
            return Ok(());
        }
        
        let byte_value = match u8::from_str_radix(input, 16) {
            Ok(v) => v,
            Err(_) => {
                self.memory_status = "Invalid hex value".to_string();
                return Err(anyhow!("Invalid hex value"));
            }
        };
        
        // Get cursor position and update memory
        let bytes_per_row = 16;
        let offset = self.get_memory_cursor_offset(bytes_per_row);
        
        let result = {
            if let Some((base_addr, data)) = &mut self.memory_data {
                if offset < data.len() {
                    // Update in-memory buffer
                    data[offset] = byte_value;
                    
                    // Write to process memory
                    let address = *base_addr + offset as u64;
                    let mut debugger = self.debugger.lock().unwrap();
                    
                    match debugger.write_memory(address, &[byte_value]) {
                        Ok(_) => {
                            // Move cursor to next byte (after we release the lock)
                            Some((address, data.len()))
                        },
                        Err(e) => {
                            return Err(anyhow!("Failed to write memory: {}", e));
                        }
                    }
                } else {
                    self.memory_status = "Position out of range".to_string();
                    None
                }
            } else {
                self.memory_status = "No memory data loaded".to_string();
                None
            }
        };
        
        // Update UI if the write was successful
        if let Some((address, data_len)) = result {
            // Now we can move the cursor
            self.move_memory_cursor(CursorDirection::Right, data_len, bytes_per_row);
            self.memory_status = format!("Wrote 0x{:02x} at 0x{:x}", byte_value, address);
        }
        
        self.memory_edit_mode = false;
        self.memory_edit_buffer.clear();
        
        Ok(())
    }
    
    /// Execute memory jump with current input
    pub fn execute_memory_jump(&mut self) -> Result<()> {
        let input = self.memory_jump_input.trim();
        if input.is_empty() {
            self.memory_jump_mode = false;
            self.memory_status = "Jump canceled - empty address".to_string();
            return Ok(());
        }
        
        // Parse the address
        let address = match u64::from_str_radix(input, 16) {
            Ok(addr) => addr,
            Err(_) => {
                self.memory_status = "Invalid hex address".to_string();
                return Err(anyhow!("Invalid hex address"));
            }
        };
        
        // Check if address is within current view
        if let Some((base_addr, data)) = &self.memory_data {
            let data_end = *base_addr + data.len() as u64;
            if address >= *base_addr && address < data_end {
                // Address is in current range, just move cursor
                let offset = (address - *base_addr) as usize;
                let bytes_per_row = 16;
                let row = offset / bytes_per_row;
                let col = offset % bytes_per_row;
                
                self.memory_cursor = (row, col);
                
                // Update scroll
                let visible_rows = 20; // Approximate
                if row < self.memory_scroll || row >= self.memory_scroll + visible_rows {
                    self.memory_scroll = row.saturating_sub(5); // Position with some context
                }
                
                self.memory_status = format!("Jumped to address 0x{:x}", address);
            } else {
                // Need to request new memory region
                let fetch_size = data.len(); // Use current view size
                self.fetch_memory(address, fetch_size)?;
            }
        } else {
            // No memory loaded yet, load default size
            const DEFAULT_SIZE: usize = 1024;
            self.fetch_memory(address, DEFAULT_SIZE)?;
        }
        
        // Add to history
        self.add_to_memory_history(address);
        
        self.memory_jump_mode = false;
        self.memory_jump_input.clear();
        
        Ok(())
    }

    /// Handle keys specifically for the memory view
    pub fn handle_memory_keys(&mut self, key: KeyEvent) -> Result<()> {
        if self.memory_search_mode {
            // Handle input mode for search
            match key.code {
                KeyCode::Char(c) => {
                    self.memory_search_input.push(c);
                },
                KeyCode::Backspace => {
                    self.memory_search_input.pop();
                },
                KeyCode::Esc => {
                    self.cancel_memory_search();
                },
                KeyCode::Enter => {
                    self.execute_memory_search()?;
                },
                _ => {}
            }
        } else if self.memory_edit_mode {
            // Handle input mode for memory editing
            match key.code {
                KeyCode::Char(c) if c.is_ascii_hexdigit() => {
                    if self.memory_edit_buffer.len() < 2 {
                        self.memory_edit_buffer.push(c);
                    }
                },
                KeyCode::Backspace => {
                    self.memory_edit_buffer.pop();
                },
                KeyCode::Esc => {
                    self.cancel_memory_edit();
                },
                KeyCode::Enter => {
                    self.execute_memory_edit()?;
                },
                _ => {}
            }
        } else if self.memory_jump_mode {
            // Handle input mode for address jump
            match key.code {
                KeyCode::Char(c) if c.is_ascii_hexdigit() => {
                    self.memory_jump_input.push(c);
                },
                KeyCode::Backspace => {
                    self.memory_jump_input.pop();
                },
                KeyCode::Esc => {
                    self.cancel_memory_jump();
                },
                KeyCode::Enter => {
                    self.execute_memory_jump()?;
                },
                _ => {}
            }
        } else {
            // Normal mode handling
            match key.code {
                // Cursor movement
                KeyCode::Up | KeyCode::Char('k') => {
                    if let Some((_, data)) = &self.memory_data {
                        self.move_memory_cursor(CursorDirection::Up, data.len(), 16);
                    }
                },
                KeyCode::Down | KeyCode::Char('j') => {
                    if let Some((_, data)) = &self.memory_data {
                        self.move_memory_cursor(CursorDirection::Down, data.len(), 16);
                    }
                },
                KeyCode::Left | KeyCode::Char('h') => {
                    if let Some((_, data)) = &self.memory_data {
                        self.move_memory_cursor(CursorDirection::Left, data.len(), 16);
                    }
                },
                KeyCode::Right | KeyCode::Char('l') => {
                    if let Some((_, data)) = &self.memory_data {
                        self.move_memory_cursor(CursorDirection::Right, data.len(), 16);
                    }
                },
                
                // Page up/down
                KeyCode::PageUp => {
                    self.memory_scroll = self.memory_scroll.saturating_sub(20);
                },
                KeyCode::PageDown => {
                    if let Some((_, data)) = &self.memory_data {
                        let total_rows = (data.len() + 16 - 1) / 16;
                        self.memory_scroll = (self.memory_scroll + 20).min(total_rows.saturating_sub(1));
                    }
                },
                KeyCode::Home => {
                    self.memory_scroll = 0;
                    self.memory_cursor = (0, 0);
                },
                KeyCode::End => {
                    if let Some((_, data)) = &self.memory_data {
                        let total_rows = (data.len() + 16 - 1) / 16;
                        self.memory_scroll = total_rows.saturating_sub(1);
                        self.memory_cursor = (total_rows.saturating_sub(1), 0);
                    }
                },
                
                // Edit memory
                KeyCode::Char('e') => {
                    self.start_memory_edit();
                },
                
                // Format switching
                KeyCode::Tab => {
                    let formats = MemoryFormat::all();
                    let current_format = self.get_memory_format();
                    let current_idx = formats.iter().position(|&f| f == current_format).unwrap_or(0);
                    let next_idx = (current_idx + 1) % formats.len();
                    self.set_memory_format(formats[next_idx]);
                    self.memory_status = format!("Format changed to: {}", formats[next_idx].as_str());
                },
                
                // Search
                KeyCode::Char('/') => {
                    self.start_memory_search();
                },
                
                // Jump to address
                KeyCode::Char('g') => {
                    self.start_memory_jump();
                },
                
                // Search result navigation
                KeyCode::Char('n') => {
                    self.next_search_result();
                },
                KeyCode::Char('N') => {
                    self.prev_search_result();
                },
                
                // History navigation
                KeyCode::Char('b') => {
                    if let Some(addr) = self.memory_history_back() {
                        self.jump_to_memory_address(addr);
                    }
                },
                KeyCode::Char('f') => {
                    if let Some(addr) = self.memory_history_forward() {
                        self.jump_to_memory_address(addr);
                    }
                },
                
                // Selection
                KeyCode::Char(' ') => {
                    if self.memory_selection.is_some() {
                        // End selection and create/copy
                        if let Some((start, end)) = self.end_memory_selection(16) {
                            if let Some((base_addr, data)) = &self.memory_data {
                                let end_adj = end.min(data.len());
                                if start < end_adj {
                                    let selection = &data[start..end_adj];
                                    // Could potentially export to clipboard or create watchpoint here
                                    self.memory_status = format!(
                                        "Selected {} bytes from 0x{:x} to 0x{:x}", 
                                        selection.len(),
                                        base_addr + start as u64,
                                        base_addr + end_adj as u64
                                    );
                                }
                            }
                        }
                    } else {
                        // Start selection
                        self.start_memory_selection();
                        self.memory_status = "Selection started. Use cursor keys and press space to complete.".to_string();
                    }
                },
                
                // Set watchpoint at cursor
                KeyCode::Char('w') => {
                    if let Some((base_addr, _)) = &self.memory_data {
                        let cursor_addr = self.get_memory_cursor_address(*base_addr, 16);
                        let mut debugger = self.debugger.lock().unwrap();
                        
                        // Default to a 1-byte write watchpoint
                        match debugger.set_watchpoint(cursor_addr, 1, crate::platform::WatchpointType::Write) {
                            Ok(_) => {
                                self.memory_status = format!("Set write watchpoint at 0x{:x}", cursor_addr);
                            },
                            Err(e) => {
                                self.memory_status = format!("Failed to set watchpoint: {}", e);
                            }
                        }
                    }
                },
                
                // Toggle read watchpoint at cursor
                KeyCode::Char('r') => {
                    if let Some((base_addr, _)) = &self.memory_data {
                        let cursor_addr = self.get_memory_cursor_address(*base_addr, 16);
                        let mut debugger = self.debugger.lock().unwrap();
                        
                        // Default to a 1-byte read watchpoint
                        match debugger.set_watchpoint(cursor_addr, 1, crate::platform::WatchpointType::Read) {
                            Ok(_) => {
                                self.memory_status = format!("Set read watchpoint at 0x{:x}", cursor_addr);
                            },
                            Err(e) => {
                                self.memory_status = format!("Failed to set watchpoint: {}", e);
                            }
                        }
                    }
                },
                
                // Toggle access (read/write) watchpoint at cursor
                KeyCode::Char('a') => {
                    if let Some((base_addr, _)) = &self.memory_data {
                        let cursor_addr = self.get_memory_cursor_address(*base_addr, 16);
                        let mut debugger = self.debugger.lock().unwrap();
                        
                        // Default to a 1-byte read/write watchpoint
                        match debugger.set_watchpoint(cursor_addr, 1, crate::platform::WatchpointType::ReadWrite) {
                            Ok(_) => {
                                self.memory_status = format!("Set read/write watchpoint at 0x{:x}", cursor_addr);
                            },
                            Err(e) => {
                                self.memory_status = format!("Failed to set watchpoint: {}", e);
                            }
                        }
                    }
                },
                
                // Remove watchpoint at cursor
                KeyCode::Char('d') => {
                    if let Some((base_addr, _)) = &self.memory_data {
                        let cursor_addr = self.get_memory_cursor_address(*base_addr, 16);
                        let mut debugger = self.debugger.lock().unwrap();
                        
                        match debugger.remove_watchpoint(cursor_addr) {
                            Ok(_) => {
                                self.memory_status = format!("Removed watchpoint at 0x{:x}", cursor_addr);
                            },
                            Err(e) => {
                                self.memory_status = format!("Failed to remove watchpoint: {}", e);
                            }
                        }
                    }
                },
                
                // Refresh memory view
                KeyCode::Char('R') => {
                    if let Some((base_addr, data_len)) = self.memory_data.as_ref().map(|(addr, data)| (*addr, data.len())) {
                        self.fetch_memory(base_addr, data_len)?;
                        self.memory_status = "Memory refreshed".to_string();
                    }
                },
                
                // Go to next memory region
                KeyCode::Char(']') => {
                    let mut next_region_addr = None;
                    let current_addr = self.memory_data.as_ref().map(|(addr, _)| *addr);
                    
                    if let Some(addr) = current_addr {
                        if let Ok(debugger) = self.debugger.lock() {
                            if let Some(memory_map) = debugger.get_memory_map() {
                                next_region_addr = memory_map.find_next_region(addr).map(|region| region.base);
                            }
                        }
                    }
                    
                    // Now handle the result outside of any debugger borrows
                    if let Some(addr) = next_region_addr {
                        self.fetch_memory(addr, 1024)?;
                        self.memory_status = format!("Navigated to next region at 0x{:x}", addr);
                    } else {
                        self.memory_status = "No next memory region found".to_string();
                    }
                },
                
                // Go to previous memory region
                KeyCode::Char('[') => {
                    let mut prev_region_addr = None;
                    let current_addr = self.memory_data.as_ref().map(|(addr, _)| *addr);
                    
                    if let Some(addr) = current_addr {
                        if let Ok(debugger) = self.debugger.lock() {
                            if let Some(memory_map) = debugger.get_memory_map() {
                                prev_region_addr = memory_map.find_prev_region(addr).map(|region| region.base);
                            }
                        }
                    }
                    
                    // Now handle the result outside of any debugger borrows
                    if let Some(addr) = prev_region_addr {
                        self.fetch_memory(addr, 1024)?;
                        self.memory_status = format!("Navigated to previous region at 0x{:x}", addr);
                    } else {
                        self.memory_status = "No previous memory region found".to_string();
                    }
                },
                
                // Display help for memory view
                KeyCode::F(1) => {
                    self.memory_status = "Memory View Commands: e=edit | /=search | g=jump | n=next result | w=watch | r/a=read/access watch | d=delete watch | []=prev/next region".to_string();
                },
                
                _ => {}
            }
        }
        
        Ok(())
    }

    /// Fetch memory from debugger
    pub fn fetch_memory(&mut self, address: u64, size: usize) -> Result<()> {
        use log::debug;
        
        // Log the operation
        debug!("Reading memory at 0x{:x} with size {}", address, size);
        
        // First get the debugger in a separate scope
        let data = {
            let mut debugger = self.debugger.lock().unwrap();
            debugger.read_memory(address, size)
        };
        
        // Process the result after releasing the lock
        match data {
            Ok(memory_data) => {
                self.memory_data = Some((address, memory_data));
                self.memory_status = format!("Loaded {} bytes from 0x{:x}", size, address);
                
                // Add to navigation history
                self.add_to_memory_history(address);
                
                Ok(())
            },
            Err(e) => {
                self.memory_status = format!("Failed to read memory: {}", e);
                Err(anyhow!("Failed to read memory: {}", e))
            }
        }
    }

    /// Handle key event
    pub fn handle_key_event(&mut self, key: KeyEvent) -> Result<bool> {
        // Check for mode-specific handling first
        if self.ui_mode == UiMode::HelpOverlay {
            // Any key closes help overlay
            self.ui_mode = UiMode::Normal;
            return Ok(true);
        }
        
        // Handle global key handlers first
        match key.code {
            KeyCode::Esc => {
                if self.ui_mode != UiMode::Normal {
                    self.ui_mode = UiMode::Normal;
                    return Ok(true);
                }
                
                // Cancel any active memory mode (search, edit, jump)
                if self.memory_search_mode {
                    self.memory_search_mode = false;
                    self.memory_search_input.clear();
                    self.memory_status = "Search canceled".to_string();
                    return Ok(true);
                } else if self.memory_edit_mode {
                    self.memory_edit_mode = false;
                    self.memory_edit_buffer.clear();
                    self.memory_status = "Edit canceled".to_string();
                    return Ok(true);
                } else if self.memory_jump_mode {
                    self.memory_jump_mode = false;
                    self.memory_jump_input.clear();
                    self.memory_status = "Jump canceled".to_string();
                    return Ok(true);
                }
            },
            _ => {}
        }
        
        // Handle view-specific key handling
        match self.current_view {
            View::Memory => {
                // If the memory view is focused, use our specialized memory key handler
                self.handle_memory_keys(key)?;
                return Ok(true);
            },
            _ => {
                // For other views, handle with the existing code
            }
        }
        
        Ok(false) // Not handled
    }
}
