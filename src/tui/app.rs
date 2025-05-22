use ratatui::{
    backend::CrosstermBackend, 
    Terminal, 
    widgets::{Block, Borders, Paragraph}, 
    layout::{Layout, Constraint, Direction, Rect}, 
    style::{Style, Color, Modifier},
    text::{Span, Line as Spans}
};
use crossterm::{
    event::{self, Event, KeyCode, KeyEvent, KeyModifiers}, 
    terminal::{enable_raw_mode, disable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen}, 
    execute
};
use std::io;
use std::time::{Duration, Instant};
use anyhow::{Result, anyhow};

use crate::debugger::core::Debugger;
use crate::tui::views::{CodeView, StackView, MemoryView, ThreadsView, CommandView, command::InputMode};

/// View types for the TUI
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum View {
    Code,
    Stack,
    Memory,
    Threads,
    Registers,
    Command,
    Help,
}

/// Commands that can be executed in the app
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Run,
    Continue,
    Step,
    StepOver,
    StepOut,
    SetBreakpoint(String),  // Symbol or address
    ClearBreakpoint(usize), // Index
    Quit,
    SwitchView(View),
    ShowHelp,
    Unknown(String),
}

// Main App struct expected by main.rs
pub struct App {
    pub debugger: Debugger,
    pub ui: TuiApp,
    pub running: bool,
    pub current_view: View,
}

impl App {
    pub fn new(debugger: Debugger) -> Result<Self> {
        let ui = TuiApp::new();
        Ok(Self {
            debugger,
            ui,
            running: true,
            current_view: View::Code,
        })
    }

    pub fn run(&mut self) -> Result<()> {
        // Run the TUI
        self.ui.run(&mut self.debugger).map_err(|e| anyhow!("TUI error: {}", e))
    }

    /// Parse a command string into a Command enum
    pub fn parse_command(&self, cmd_str: &str) -> Command {
        let cmd_str = cmd_str.trim();
        
        // Split the command into parts
        let parts: Vec<&str> = cmd_str.split_whitespace().collect();
        if parts.is_empty() {
            return Command::Unknown("Empty command".to_string());
        }
        
        match parts[0] {
            "run" | "r" => Command::Run,
            "continue" | "c" => Command::Continue,
            "step" | "s" => Command::Step,
            "next" | "n" => Command::StepOver,
            "finish" | "f" => Command::StepOut,
            "break" | "b" => {
                if parts.len() < 2 {
                    Command::Unknown("Missing breakpoint location".to_string())
                } else {
                    Command::SetBreakpoint(parts[1].to_string())
                }
            }
            "clear" => {
                if parts.len() < 2 {
                    Command::Unknown("Missing breakpoint index".to_string())
                } else {
                    match parts[1].parse::<usize>() {
                        Ok(idx) => Command::ClearBreakpoint(idx),
                        Err(_) => Command::Unknown(format!("Invalid breakpoint index: {}", parts[1])),
                    }
                }
            }
            "quit" | "q" => Command::Quit,
            "help" | "h" => Command::ShowHelp,
            "view" => {
                if parts.len() < 2 {
                    Command::Unknown("Missing view name".to_string())
                } else {
                    match parts[1] {
                        "code" => Command::SwitchView(View::Code),
                        "stack" => Command::SwitchView(View::Stack),
                        "memory" => Command::SwitchView(View::Memory),
                        "threads" => Command::SwitchView(View::Threads),
                        "registers" | "regs" => Command::SwitchView(View::Registers),
                        _ => Command::Unknown(format!("Unknown view: {}", parts[1])),
                    }
                }
            }
            _ => Command::Unknown(format!("Unknown command: {}", parts[0])),
        }
    }
}

// Enhanced TUI implementation using the view components
pub struct TuiApp {
    pub should_quit: bool,
    pub active_pane: usize,
    pub pane_titles: Vec<&'static str>,
    pub help_visible: bool,
    pub last_tick: Instant,
    pub tick_rate: Duration,
    pub status: String,
    
    // View components
    code_view: CodeView,
    stack_view: StackView,
    memory_view: MemoryView,
    threads_view: ThreadsView,
    command_view: CommandView,
}

impl TuiApp {
    pub fn new() -> Self {
        Self {
            should_quit: false,
            active_pane: 0,
            pane_titles: vec!["Code", "Stack", "Memory", "Threads"],
            help_visible: false,
            last_tick: Instant::now(),
            tick_rate: Duration::from_millis(250),
            status: String::from("Ready"),
            
            // Initialize view components
            code_view: CodeView::new(),
            stack_view: StackView::new(),
            memory_view: MemoryView::new(),
            threads_view: ThreadsView::new(),
            command_view: CommandView::new(),
        }
    }

    pub fn run(&mut self, debugger: &mut Debugger) -> io::Result<()> {
        // Setup terminal
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen)?;
        let backend = CrosstermBackend::new(stdout);
        let mut terminal = Terminal::new(backend)?;
        
        // Main event loop
        loop {
            // Draw the UI
            terminal.draw(|f| {
                self.render_ui(f, debugger);
            })?;
            
            // Update state
            self.update();
            
            // Handle events
            if self.handle_events(debugger)? {
                break;
            }
        }
        
        // Restore terminal
        disable_raw_mode()?;
        execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
        
        Ok(())
    }
    
    fn render_ui(&self, f: &mut ratatui::Frame, debugger: &Debugger) {
        // Create the main layout with a status bar at the top and command bar at the bottom
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(1),  // Status bar
                Constraint::Min(10),    // Main content
                Constraint::Length(3),  // Command bar
            ])
            .split(f.size());
            
        // Render status bar
        self.render_status_bar(f, chunks[0]);
        
        // If help is visible, render the help screen
        if self.help_visible {
            self.render_help(f, chunks[1]);
        } else {
            // Split the main area into panes
            let main_panes = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([
                    Constraint::Percentage(40),
                    Constraint::Percentage(20),
                    Constraint::Percentage(20),
                    Constraint::Percentage(20),
                ])
                .split(chunks[1]);
            
            // Render each view component
            self.code_view.render(f, main_panes[0], debugger);
            self.stack_view.render(f, main_panes[1], debugger);
            self.memory_view.render(f, main_panes[2], debugger);
            self.threads_view.render(f, main_panes[3], debugger);
            
            // Highlight the active pane
            let active_block = Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Yellow));
            
            // Apply highlight to the active pane
            match self.active_pane {
                0 => f.render_widget(active_block, main_panes[0]),
                1 => f.render_widget(active_block, main_panes[1]),
                2 => f.render_widget(active_block, main_panes[2]),
                3 => f.render_widget(active_block, main_panes[3]),
                _ => {}
            };
        }
        
        // Render command bar
        self.command_view.render(f, chunks[2], debugger);
    }
    
    fn render_status_bar(&self, f: &mut ratatui::Frame, area: Rect) {
        let status_text = vec![
            Span::styled("RUSTCAT", Style::default().fg(Color::LightCyan).add_modifier(Modifier::BOLD)),
            Span::raw(" | "),
            Span::styled(&self.status, Style::default().fg(Color::White)),
            Span::raw(" | "),
            Span::styled("Press '?' for help", Style::default().fg(Color::DarkGray)),
        ];
        
        let status_line = Spans::from(status_text);
        let status_para = Paragraph::new(vec![status_line])
            .style(Style::default().bg(Color::Black));
        
        f.render_widget(status_para, area);
    }
    
    fn render_help(&self, f: &mut ratatui::Frame, area: Rect) {
        let help_block = Block::default()
            .title("Help")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::LightBlue));
        
        let help_text = vec![
            Spans::from(vec![
                Span::styled("RUSTCAT Keyboard Controls", Style::default().fg(Color::LightCyan).add_modifier(Modifier::BOLD))
            ]),
            Spans::from(vec![Span::raw("")]),
            Spans::from(vec![
                Span::styled("q", Style::default().fg(Color::Yellow)),
                Span::raw(" - Quit")
            ]),
            Spans::from(vec![
                Span::styled("h/l", Style::default().fg(Color::Yellow)),
                Span::raw(" - Navigate between panes")
            ]),
            Spans::from(vec![
                Span::styled(":", Style::default().fg(Color::Yellow)),
                Span::raw(" - Enter command mode")
            ]),
            Spans::from(vec![
                Span::styled("?", Style::default().fg(Color::Yellow)),
                Span::raw(" - Toggle help view")
            ]),
            Spans::from(vec![Span::raw("")]),
            Spans::from(vec![
                Span::styled("Commands:", Style::default().add_modifier(Modifier::BOLD))
            ]),
            Spans::from(vec![
                Span::raw("run, r            - Run/restart program")
            ]),
            Spans::from(vec![
                Span::raw("continue, c       - Continue execution")
            ]),
            Spans::from(vec![
                Span::raw("step, s           - Step instruction")
            ]),
            Spans::from(vec![
                Span::raw("next, n           - Step over")
            ]),
            Spans::from(vec![
                Span::raw("finish, f         - Step out")
            ]),
            Spans::from(vec![
                Span::raw("break <addr>, b   - Set breakpoint")
            ]),
            Spans::from(vec![
                Span::raw("clear <index>     - Clear breakpoint")
            ]),
            Spans::from(vec![
                Span::raw("quit, q           - Quit")
            ]),
            Spans::from(vec![
                Span::raw("help, h           - Show help")
            ]),
        ];
        
        let help_para = Paragraph::new(help_text)
            .block(help_block);
        
        f.render_widget(help_para, area);
    }
    
    fn handle_events(&mut self, debugger: &mut Debugger) -> io::Result<bool> {
        // Poll for events with a timeout
        if event::poll(std::time::Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                // First check if the command view wants to handle this key
                if self.command_view.input_mode == InputMode::Editing {
                    if let Some(cmd) = self.command_view.handle_key(key) {
                        // Process the command
                        self.process_command(cmd, debugger);
                    }
                } else {
                    // Handle keys in normal mode
                    match key.code {
                        KeyCode::Char('q') => {
                            self.should_quit = true;
                        }
                        KeyCode::Char('h') => {
                            if !self.help_visible && self.active_pane > 0 {
                                self.active_pane -= 1;
                            }
                        }
                        KeyCode::Char('l') => {
                            if !self.help_visible && self.active_pane < self.pane_titles.len() - 1 {
                                self.active_pane += 1;
                            }
                        }
                        KeyCode::Char(':') => {
                            // Forward this key to command view
                            self.command_view.handle_key(key);
                        }
                        KeyCode::Char('?') => {
                            // Toggle help view
                            self.help_visible = !self.help_visible;
                        }
                        KeyCode::Esc => {
                            // Exit help view if it's visible
                            if self.help_visible {
                                self.help_visible = false;
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
        
        // Check if we should quit
        Ok(self.should_quit)
    }
    
    fn update(&mut self) {
        // Check if we need to update timed components
        let now = Instant::now();
        if now.duration_since(self.last_tick) >= self.tick_rate {
            self.last_tick = now;
            
            // Update command view
            self.command_view.update();
        }
    }
    
    fn process_command(&mut self, command: Command, debugger: &mut Debugger) {
        match command {
            Command::Quit => {
                self.should_quit = true;
            }
            Command::ShowHelp => {
                self.help_visible = true;
            }
            Command::SwitchView(view) => {
                match view {
                    View::Code => self.active_pane = 0,
                    View::Stack => self.active_pane = 1,
                    View::Memory => self.active_pane = 2,
                    View::Threads => self.active_pane = 3,
                    _ => {}
                }
                
                // Also hide help if it's visible
                self.help_visible = false;
            }
            Command::Run => {
                self.status = String::from("Running program");
                match debugger.run() {
                    Ok(_) => {
                        self.command_view.show_message("Program running".to_string(), Duration::from_secs(3));
                    },
                    Err(e) => {
                        self.command_view.show_message(format!("Error: {}", e), Duration::from_secs(5));
                        self.status = String::from("Error running program");
                    }
                }
            }
            Command::Continue => {
                self.status = String::from("Continuing execution");
                match debugger.continue_execution() {
                    Ok(_) => {
                        self.command_view.show_message("Program continuing".to_string(), Duration::from_secs(3));
                    },
                    Err(e) => {
                        self.command_view.show_message(format!("Error: {}", e), Duration::from_secs(5));
                        self.status = String::from("Error continuing execution");
                    }
                }
            }
            Command::Step => {
                self.status = String::from("Stepping instruction");
                match debugger.step() {
                    Ok(_) => {
                        self.command_view.show_message("Stepped".to_string(), Duration::from_secs(2));
                    },
                    Err(e) => {
                        self.command_view.show_message(format!("Error: {}", e), Duration::from_secs(5));
                        self.status = String::from("Error stepping");
                    }
                }
            }
            Command::StepOver => {
                self.status = String::from("Stepping over");
                match debugger.step_over() {
                    Ok(_) => {
                        self.command_view.show_message("Stepped over".to_string(), Duration::from_secs(2));
                    },
                    Err(e) => {
                        self.command_view.show_message(format!("Error: {}", e), Duration::from_secs(5));
                        self.status = String::from("Error stepping over");
                    }
                }
            }
            Command::StepOut => {
                self.status = String::from("Stepping out");
                match debugger.step_out() {
                    Ok(_) => {
                        self.command_view.show_message("Stepped out".to_string(), Duration::from_secs(2));
                    },
                    Err(e) => {
                        self.command_view.show_message(format!("Error: {}", e), Duration::from_secs(5));
                        self.status = String::from("Error stepping out");
                    }
                }
            }
            Command::SetBreakpoint(location) => {
                self.status = format!("Setting breakpoint at {}", location);
                
                // Parse the location: could be a symbol name or an address
                let result = if location.starts_with("0x") {
                    // Parse hex address
                    match u64::from_str_radix(&location[2..], 16) {
                        Ok(addr) => debugger.set_breakpoint(addr),
                        Err(_) => Err(anyhow!("Invalid hex address: {}", location))
                    }
                } else if let Ok(addr) = location.parse::<u64>() {
                    // Decimal address
                    debugger.set_breakpoint(addr)
                } else {
                    // Try as a symbol name
                    debugger.set_breakpoint_by_name(&location)
                };
                
                match result {
                    Ok(_) => {
                        self.command_view.show_message(format!("Breakpoint set at {}", location), Duration::from_secs(3));
                    },
                    Err(e) => {
                        self.command_view.show_message(format!("Error: {}", e), Duration::from_secs(5));
                        self.status = String::from("Error setting breakpoint");
                    }
                }
            }
            Command::ClearBreakpoint(index) => {
                self.status = format!("Clearing breakpoint {}", index);
                
                // Get all breakpoints and check if the index exists
                let breakpoints = debugger.get_breakpoints();
                
                if index < breakpoints.len() {
                    // Get the address of the breakpoint at the specified index
                    let addr = breakpoints[index].address();
                    
                    match debugger.remove_breakpoint(addr) {
                        Ok(_) => {
                            self.command_view.show_message(format!("Breakpoint {} cleared", index), Duration::from_secs(3));
                        },
                        Err(e) => {
                            self.command_view.show_message(format!("Error: {}", e), Duration::from_secs(5));
                            self.status = String::from("Error clearing breakpoint");
                        }
                    }
                } else {
                    self.command_view.show_message(format!("Breakpoint {} not found", index), Duration::from_secs(3));
                    self.status = String::from("Breakpoint not found");
                }
            }
            Command::Unknown(msg) => {
                self.command_view.show_message(format!("Error: {}", msg), Duration::from_secs(3));
            }
        }
    }
}
