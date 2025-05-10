use std::io;
use std::sync::{Arc, Mutex};
use std::collections::{VecDeque, HashMap};
use std::time::{Duration, Instant};
use std::fs::File;
use std::io::Write;
use std::sync::mpsc;

use anyhow::{Result, Context, anyhow};
use crossterm::event::{Event, KeyCode, KeyModifiers, MouseEvent, MouseEventKind, MouseButton};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode};
use crossterm::execute;
use crossterm::event::EnableMouseCapture;
use crossterm::event::DisableMouseCapture;
use log::{LevelFilter, Level};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::Rect;
use ratatui::Terminal;
use regex::Regex;

use crate::debugger::core::Debugger;
use crate::debugger::breakpoint::Breakpoint;
use crate::tui::ui::draw_ui;
use crate::tui::ui::setup_log_capture;
use crate::tui::events::Events;

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
    
    // Control commands
    Help(Option<String>),  // Show help for command
    Set(String, String),   // Set variable
    Source(String),        // Execute commands from file
    
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

/// Command queue item
#[derive(Debug)]
struct QueuedCommand {
    command: Command,
    timestamp: Instant,
    retries: usize,
}

/// Application state
pub struct App {
    /// The debugger instance
    debugger: Arc<Mutex<Debugger>>,
    /// Is the application running?
    running: bool,
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
    command_history: VecDeque<String>,
    /// Current history position
    command_history_pos: Option<usize>,
    /// Command completion items
    completion_items: Vec<CompletionItem>,
    /// Selected completion item
    selected_completion: usize,
    /// Command queue for debugger operations
    command_queue: VecDeque<QueuedCommand>,
    /// Context menu selection
    context_menu_selected: usize,
    /// Documentation for commands
    command_docs: HashMap<String, String>,
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
            command_docs: command_docs,
        })
    }

    /// Get filtered log messages based on current level filter
    pub fn filtered_logs(&self) -> Vec<&String> {
        let filtered: Vec<&String> = self.log_messages
            .iter()
            .filter(|msg| {
                let base_filter = match self.log_filter {
                    LogFilter::Debug => true,
                    LogFilter::Info => !msg.contains("[DEBUG]"),
                    LogFilter::Warn => msg.contains("[WARN]") || msg.contains("[ERROR]"),
                    LogFilter::Error => msg.contains("[ERROR]"),
                    LogFilter::Custom => true, // For custom filtering, apply regex separately
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
    pub fn cycle_log_filter(&mut self) {
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
    
    /// Set a custom regex filter for logs
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
    
    /// Search logs for a specific text
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
        if !self.log_search_results.is_empty() {
            self.log_search_index = (self.log_search_index + 1) % self.log_search_results.len();
            // Update scroll position to show the current result
            if let Some(&result_idx) = self.log_search_results.get(self.log_search_index) {
                self.log_scroll = result_idx;
            }
        }
    }
    
    /// Navigate to previous search result
    pub fn prev_search_result(&mut self) {
        if !self.log_search_results.is_empty() {
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
        writeln!(file, "\n--- Export completed at {} ---", timestamp).context("Failed to write export timestamp")?;
        
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
        self.command_queue.push_back(QueuedCommand {
            command,
            timestamp: Instant::now(),
            retries: 0,
        });
    }
    
    /// Process queued commands
    fn process_command_queue(&mut self) -> Result<()> {
        // Only try to process if there are commands in the queue
        if self.command_queue.is_empty() {
            return Ok(());
        }
        
        // Try to get the debugger lock with timeout
        match self.debugger.try_lock() {
            Ok(mut debugger) => {
                // Process the first command in the queue
                if let Some(queued_cmd) = self.command_queue.pop_front() {
                    let result = match queued_cmd.command {
                        Command::Break(location) => {
                            let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
                            // Try to parse as a memory address first
                            if location.starts_with("0x") || location.starts_with("0X") {
                                // Parse hex address
                                let addr_str = if location.starts_with("0x") || location.starts_with("0X") {
                                    &location[2..]
                                } else {
                                    &location
                                };
                                
                                match u64::from_str_radix(addr_str, 16) {
                                    Ok(addr) => {
                                        match debugger.set_breakpoint(addr) {
                                            Ok(_) => {
                                                self.log_messages.push_back(
                                                    format!("[{}] [INFO] Breakpoint set at {} (0x{:x})", timestamp, location, addr)
                                                );
                                                Ok(())
                                            },
                                            Err(e) => Err(anyhow!("Failed to set breakpoint: {}", e))
                                        }
                                    },
                                    Err(e) => Err(anyhow!("Failed to parse address: {}", e))
                                }
                            } else if let Ok(addr) = location.parse::<u64>() {
                                // Parse decimal address
                                match debugger.set_breakpoint(addr) {
                                    Ok(_) => {
                                        self.log_messages.push_back(
                                            format!("[{}] [INFO] Breakpoint set at {} (0x{:x})", timestamp, location, addr)
                                        );
                                        Ok(())
                                    },
                                    Err(e) => Err(anyhow!("Failed to set breakpoint: {}", e))
                                }
                            } else {
                                // Try as function name
                                match debugger.set_breakpoint_by_name(&location) {
                                    Ok(_) => {
                                        self.log_messages.push_back(
                                            format!("[{}] [INFO] Breakpoint set at function {}", timestamp, location)
                                        );
                                        Ok(())
                                    },
                                    Err(e) => Err(anyhow!("Failed to set breakpoint: {}", e))
                                }
                            }
                        },
                        Command::Continue => {
                            debugger.continue_execution().context("Failed to continue execution")
                        },
                        Command::Step => {
                            // Try to step into function
                            let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
                            match debugger.step() {
                                Ok(_) => {
                                    self.log_messages.push_back(
                                        format!("[{}] [INFO] Stepped into instruction", timestamp)
                                    );
                                    Ok(())
                                },
                                Err(e) => Err(anyhow!("Step failed: {}", e))
                            }
                        },
                        Command::Next => {
                            // Try to step over function (using step until step_over is implemented)
                            let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
                            match debugger.step() {  // Use step() until step_over() is implemented
                                Ok(_) => {
                                    self.log_messages.push_back(
                                        format!("[{}] [INFO] Stepped over instruction", timestamp)
                                    );
                                    Ok(())
                                },
                                Err(e) => Err(anyhow!("Step over failed: {}", e))
                            }
                        },
                        Command::Run => {
                            debugger.run().context("Failed to run program")
                        },
                        Command::Quit => {
                            self.running = false;
                            Ok(())
                        },
                        Command::Print(expr) => {
                            // Placeholder for expression evaluation
                            let value = if expr.starts_with("0x") {
                                // Try to parse as hex
                                if let Ok(val) = u64::from_str_radix(&expr[2..], 16) {
                                    format!("0x{:x} ({})", val, val)
                                } else {
                                    "Error: Invalid hex expression".to_string()
                                }
                            } else if let Ok(val) = expr.parse::<u64>() {
                                // Try to parse as decimal
                                format!("{} (0x{:x})", val, val)
                            } else {
                                // Just return a placeholder value
                                format!("<{}> (type unknown)", expr)
                            };
                            
                            let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
                            self.log_messages.push_back(
                                format!("[{}] [INFO] {} = {}", timestamp, expr, value)
                            );
                            Ok(())
                        },
                        // Handle other commands...
                        _ => {
                            let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
                            self.log_messages.push_back(
                                format!("[{}] [WARN] Command not implemented yet", timestamp)
                            );
                            Ok(())
                        }
                    };
                    
                    // Handle command result
                    if let Err(e) = result {
                        let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
                        self.log_messages.push_back(
                            format!("[{}] [ERROR] Command failed: {}", timestamp, e)
                        );
                    }
                    
                    // Update state directly while still holding the lock
                    self.breakpoints = debugger.get_breakpoints().to_vec();
                    self.breakpoint_count = self.breakpoints.len();
                    self.current_function = Some("main".to_string());
                    self.program_running = false;
                }
            },
            Err(_) => {
                // If we couldn't get the lock, check if we should retry
                if let Some(cmd) = self.command_queue.front_mut() {
                    // Only retry up to 3 times and only for commands less than 5 seconds old
                    if cmd.retries < 3 && cmd.timestamp.elapsed() < Duration::from_secs(5) {
                        cmd.retries += 1;
                        // Log retry attempt
                        let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
                        self.log_messages.push_back(
                            format!("[{}] [WARN] Retrying command (attempt {})", timestamp, cmd.retries)
                        );
                    } else {
                        // Command expired or too many retries
                        let cmd = self.command_queue.pop_front().unwrap();
                        let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
                        self.log_messages.push_back(
                            format!("[{}] [ERROR] Command timed out after {} retries", timestamp, cmd.retries)
                        );
                    }
                }
            }
        }
        
        Ok(())
    }
    
    /// Parse a command string into a structured Command
    pub fn parse_command(&self, cmd_str: &str) -> Command {
        let cmd_str = cmd_str.trim();
        
        // Empty command
        if cmd_str.is_empty() {
            return Command::Unknown("".to_string());
        }
        
        // Split by whitespace to get command and args
        let parts: Vec<&str> = cmd_str.split_whitespace().collect();
        let cmd_name = parts[0].to_lowercase();
        let args = &parts[1..];
        
        match cmd_name.as_str() {
            "b" | "break" => {
                if args.is_empty() {
                    Command::Unknown("break requires an address or function name".to_string())
                } else {
                    Command::Break(args.join(" "))
                }
            },
            "c" | "continue" => Command::Continue,
            "s" | "step" => Command::Step,
            "n" | "next" => Command::Next,
            "r" | "run" => Command::Run,
            "q" | "quit" => Command::Quit,
            "p" | "print" => {
                if args.is_empty() {
                    Command::Unknown("print requires an expression".to_string())
                } else {
                    Command::Print(args.join(" "))
                }
            },
            "h" | "help" => {
                if args.is_empty() {
                    Command::Help(None)
                } else {
                    Command::Help(Some(args[0].to_string()))
                }
            },
            _ => Command::Unknown(cmd_str.to_string()),
        }
    }
    
    /// Get command completions based on current input
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
            if let Ok(debugger) = self.debugger.try_lock() {
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
                    if input.find(' ').map_or(false, |pos| func.text.contains(&input[pos + 1..])) {
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
    /// Update UI state based on debugger state
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
    
    /// Run the application main loop
    pub fn run(&mut self) -> Result<()> {
        // Setup terminal
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(stdout, EnableMouseCapture)?;
        
        let backend = CrosstermBackend::new(stdout);
        let mut terminal = Terminal::new(backend)?;
        terminal.clear()?;

        // Main loop
        while self.running {
            // Process any new log messages
            self.process_log_messages();
            
            // Process command queue
            if let Err(e) = self.process_command_queue() {
                let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
                self.log_messages.push_back(
                    format!("[{}] [ERROR] Command queue error: {}", timestamp, e)
                );
            }
            
            // Only refresh UI at most 30 times per second
            let now = Instant::now();
            if now.duration_since(self.last_refresh) >= Duration::from_millis(33) {
                // Draw UI
                terminal.draw(|f| draw_ui(f, self))?;
                self.last_refresh = now;
            }

            // Handle input (non-blocking)
            if let Ok(event) = self.events.next() {
                self.handle_input(event)?;
            }
        }

        // Restore terminal
        disable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(stdout, DisableMouseCapture)?;
        terminal.clear()?;

        Ok(())
    }

    /// Handle input events
    fn handle_input(&mut self, event: Event) -> Result<()> {
        match event {
            Event::Key(key_event) => {
                // Global key handler regardless of active block
                match key_event.code {
                    // Quit - Global
                    KeyCode::Char('q') if key_event.modifiers.is_empty() => {
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
                        match key_event.code {
                            // Change view with number keys
                            KeyCode::Char('1') => self.current_view = View::Code,
                            KeyCode::Char('2') => self.current_view = View::Memory,
                            KeyCode::Char('3') => self.current_view = View::Registers,
                            KeyCode::Char('4') => self.current_view = View::Stack,
                            KeyCode::Char('5') => self.current_view = View::Threads,
                            KeyCode::Char('6') => self.current_view = View::Command,
                            
                            // Legacy view keys
                            KeyCode::Char('c') => self.current_view = View::Code,
                            KeyCode::Char('m') => self.current_view = View::Memory,
                            KeyCode::Char('r') => self.current_view = View::Registers,
                            // 's' key is also used for stepping, so use a modifier key instead
                            KeyCode::Char('w') => self.current_view = View::Stack, // Using 'w' for 'Stack'
                            KeyCode::Char('t') => self.current_view = View::Threads,
                            
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
                        match key_event.code {
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
                        match key_event.code {
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
                            KeyCode::Char('f') if key_event.modifiers.contains(KeyModifiers::CONTROL) => {
                                self.ui_mode = UiMode::LogSearch;
                                self.command_input.clear(); // Reuse command input for search
                                self.active_block = ActiveBlock::CommandInput;
                            },
                            KeyCode::Char('n') if key_event.modifiers.contains(KeyModifiers::CONTROL) => {
                                self.next_search_result();
                            },
                            KeyCode::Char('p') if key_event.modifiers.contains(KeyModifiers::CONTROL) => {
                                self.prev_search_result();
                            },
                            KeyCode::Char('e') if key_event.modifiers.contains(KeyModifiers::CONTROL) => {
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
                            KeyCode::Char('l') if key_event.modifiers.contains(KeyModifiers::CONTROL) => {
                                // Cycle log filter
                                self.cycle_log_filter();
                            },
                            _ => {},
                        }
                    },
                }
            },
            
            Event::Mouse(mouse_event) => {
                self.mouse_position = (mouse_event.column, mouse_event.row);
                
                // Handle different mouse modes
                match self.ui_mode {
                    UiMode::ContextMenu => {
                        if let MouseEventKind::Down(MouseButton::Left) = mouse_event.kind {
                            // Handle context menu selection
                            // We would select menu item based on position
                            self.ui_mode = UiMode::Normal;
                            self.context_menu_position = None;
                        } else if let MouseEventKind::Down(MouseButton::Right) = mouse_event.kind {
                            // Right click again to dismiss
                            self.ui_mode = UiMode::Normal;
                            self.context_menu_position = None;
                        }
                    },
                    _ => {
                        match mouse_event.kind {
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
}
