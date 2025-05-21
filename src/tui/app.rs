use ratatui::{
    backend::CrosstermBackend, 
    Terminal, 
    widgets::{Block, Borders}, 
    layout::{Layout, Constraint, Direction}, 
    style::{Style, Color}
};
use crossterm::{event::{self, Event, KeyCode, KeyEvent}, terminal::{enable_raw_mode, disable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen}, execute};
use std::io;
use anyhow::{Result, anyhow};

use crate::debugger::core::Debugger;
use crate::tui::views::{CodeView, StackView, MemoryView, ThreadsView};

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
        self.ui.run(&self.debugger).map_err(|e| anyhow!("TUI error: {}", e))
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
    
    // View components
    code_view: CodeView,
    stack_view: StackView,
    memory_view: MemoryView,
    threads_view: ThreadsView,
}

impl TuiApp {
    pub fn new() -> Self {
        Self {
            should_quit: false,
            active_pane: 0,
            pane_titles: vec!["Code", "Stack", "Memory", "Threads"],
            
            // Initialize view components
            code_view: CodeView::new(),
            stack_view: StackView::new(),
            memory_view: MemoryView::new(),
            threads_view: ThreadsView::new(),
        }
    }

    pub fn run(&mut self, debugger: &Debugger) -> io::Result<()> {
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen)?;
        let backend = CrosstermBackend::new(stdout);
        let mut terminal = Terminal::new(backend)?;
        
        loop {
            terminal.draw(|f| {
                let chunks = Layout::default()
                    .direction(Direction::Horizontal)
                    .constraints([
                        Constraint::Percentage(40),
                        Constraint::Percentage(20),
                        Constraint::Percentage(20),
                        Constraint::Percentage(20),
                    ])
                    .split(f.size());
                
                // Render each view component
                self.code_view.render(f, chunks[0], debugger);
                self.stack_view.render(f, chunks[1], debugger);
                self.memory_view.render(f, chunks[2], debugger);
                self.threads_view.render(f, chunks[3], debugger);
                
                // Highlight the active pane
                let block = Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Yellow));
                
                // Apply highlight to the active pane
                match self.active_pane {
                    0 => f.render_widget(block, chunks[0]),
                    1 => f.render_widget(block, chunks[1]),
                    2 => f.render_widget(block, chunks[2]),
                    3 => f.render_widget(block, chunks[3]),
                    _ => {}
                };
            })?;
            
            if event::poll(std::time::Duration::from_millis(100))? {
                if let Event::Key(KeyEvent { code, .. }) = event::read()? {
                    match code {
                        KeyCode::Char('q') => {
                            self.should_quit = true;
                            break;
                        }
                        KeyCode::Char('h') => {
                            if self.active_pane > 0 { self.active_pane -= 1; }
                        }
                        KeyCode::Char('l') => {
                            if self.active_pane < self.pane_titles.len() - 1 { self.active_pane += 1; }
                        }
                        _ => {}
                    }
                }
            }
            
            if self.should_quit {
                break;
            }
        }
        
        disable_raw_mode()?;
        execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
        Ok(())
    }
}
