#![allow(clippy::uninlined_format_args)]
#![allow(clippy::items_after_statements)]
#![allow(clippy::option_if_let_else)]
#![allow(clippy::must_use_candidate)]

use ratatui::{
    backend::Backend,
    layout::{Constraint, Direction, Layout, Rect, Alignment},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Padding, Tabs, Paragraph, BorderType, List, ListItem, ListState},
    symbols,
    Frame,
};

use std::sync::mpsc;

use crate::tui::app::{App, View, ActiveBlock, LogFilter};
use crate::tui::views::{CodeView, CommandView, draw_memory_view, draw_thread_view, draw_call_stack_view, draw_registers_view, draw_trace_view, VariablesView};

/// Set up log capturing for UI display
pub fn setup_log_capture() -> mpsc::Receiver<String> {
    let (_tx, rx) = mpsc::channel();
    
    // Create a custom logger that sends log messages to our channel
    /// Logger that sends messages to a channel
    #[allow(dead_code)]
    struct ChannelLogger {
        sender: mpsc::Sender<String>,
    }
    
    impl log::Log for ChannelLogger {
        fn enabled(&self, metadata: &log::Metadata) -> bool {
            metadata.level() <= log::Level::Debug
        }
        
        fn log(&self, record: &log::Record) {
            if self.enabled(record.metadata()) {
                let log_message = format!("[{}] {}: {}", 
                    record.level(),
                    record.target(),
                    record.args()
                );
                let _ = self.sender.send(log_message);
            }
        }
        
        fn flush(&self) {}
    }
    
    // Set up the logger (this would normally be done in main.rs)
    // but we're just setting up the channel here
    
    rx
}

/// Main UI drawing function
pub fn draw_ui<B: Backend>(f: &mut Frame<B>, app: &mut App) {
    // Create main layout with 4 parts:
    // 1. Title bar with tabs (top)
    // 2. Main content area (middle)
    // 3. Log area (resizable, below main)
    // 4. Status bar (bottom)
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([
            Constraint::Length(3),     // Title bar
            Constraint::Min(15),       // Main content
            Constraint::Length(7),     // Log view
            Constraint::Length(3),     // Status bar
        ])
        .split(f.size());

    // Draw title bar
    draw_title_bar(f, app, chunks[0]);
    
    // Draw main content area
    draw_main_area(f, app, chunks[1]);
    
    // Draw log area
    draw_log_area(f, app, chunks[2]);
    
    // Draw status bar
    draw_status_bar(f, app, chunks[3]);
}

/// Draw the title bar with tabs
fn draw_title_bar<B: Backend>(f: &mut Frame<B>, app: &mut App, area: Rect) {
    // Create enhanced tab titles with keyboard shortcut hints
    let titles = vec![
        Span::styled("[1] Code", 
            if matches!(app.current_view, View::Code) { 
                Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)
            } else { 
                Style::default()
            }
        ),
        Span::styled("[2] Memory", 
            if matches!(app.current_view, View::Memory) { 
                Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)
            } else { 
                Style::default()
            }
        ),
        Span::styled("[3] Registers", 
            if matches!(app.current_view, View::Registers) { 
                Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)
            } else { 
                Style::default()
            }
        ),
        Span::styled("[4] Stack", 
            if matches!(app.current_view, View::Stack) { 
                Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)
            } else { 
                Style::default()
            }
        ),
        Span::styled("[5] Threads", 
            if matches!(app.current_view, View::Threads) { 
                Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)
            } else { 
                Style::default()
            }
        ),
        Span::styled("[6] Trace", 
            if matches!(app.current_view, View::Trace) { 
                Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)
            } else { 
                Style::default()
            }
        ),
        Span::styled("[7] Variables", 
            if matches!(app.current_view, View::Variables) { 
                Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)
            } else { 
                Style::default()
            }
        ),
        Span::styled("[8] Command", 
            if matches!(app.current_view, View::Command) { 
                Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)
            } else { 
                Style::default()
            }
        ),
    ];
    
    let tabs = Tabs::new(vec![Line::from(titles)])
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .title(Span::styled("RUSTCAT", Style::default().add_modifier(Modifier::BOLD)))
                .title_alignment(ratatui::layout::Alignment::Center)
        )
        .divider(symbols::line::VERTICAL)
        .highlight_style(Style::default().bg(Color::DarkGray))
        .select(match app.current_view {
            View::Code => 0,
            View::Memory => 1,
            View::Registers => 2,
            View::Stack => 3,
            View::Threads => 4,
            View::Trace => 5,
            View::Variables => 6,
            View::Command => 7,
        });
    
    f.render_widget(tabs, area);
}

/// Draw the main content area based on current view
fn draw_main_area<B: Backend>(f: &mut Frame<B>, app: &mut App, area: Rect) {
    match app.current_view {
        View::Code => {
            let code_view = CodeView::new();
            code_view.render(f, area);
        },
        View::Memory => {
            // Use our enhanced memory view
            // Check if app has memory data to display
            if let Some(last_memory) = app.get_memory_data() {
                let (address, data) = last_memory;
                
                // Create a layout with space for a format selector at the bottom
                let chunks = Layout::default()
                    .direction(Direction::Vertical)
                    .constraints([
                        Constraint::Min(5),       // Memory view
                        Constraint::Length(3),    // Format selector
                    ])
                    .split(area);
                
                // Display memory data
                draw_memory_view(f, app, chunks[0], Some(data), address);
                
                // Display format selector
                let format_names = [
                    "Hex", "ASCII", "UTF8", "U8", "U16", "U32", "U64", "F32", "F64"
                ];
                
                let _current_format = app.get_memory_format().as_str();
                let format_text = format!("Format: [{}]", format_names.join("] ["));
                
                let paragraph = Paragraph::new(format_text)
                    .style(Style::default())
                    .alignment(Alignment::Center)
                    .block(Block::default().borders(Borders::TOP));
                
                f.render_widget(paragraph, chunks[1]);
            } else {
                // No memory loaded yet, show empty view
                draw_memory_view(f, app, area, None, 0);
            }
        },
        View::Registers => {
            draw_registers_view(f, app, area);
        },
        View::Threads => {
            // Use our enhanced thread view
            draw_thread_view(f, app, area);
        },
        View::Stack => {
            // Use our enhanced call stack view
            draw_call_stack_view(f, app, area);
        },
        View::Trace => {
            // Use our function call trace view
            draw_trace_view(f, app, area);
        },
        View::Variables => {
            // Use the variables view
            let variables_view = VariablesView::new();
            variables_view.render(f, area, app);
        },
        View::Command => {
            let command_view = CommandView::new();
            command_view.render(f, area, app);
        },
    }
}

/// Draw the log area
fn draw_log_area<B: Backend>(f: &mut Frame<B>, app: &mut App, area: Rect) {
    // Get filtered logs based on current filter level
    let filtered_logs = app.filtered_logs();
    
    // Create list items from logs
    let log_items: Vec<ListItem> = filtered_logs
        .iter()
        .map(|log| {
            let style = if log.contains("[ERROR]") {
                Style::default().fg(Color::Red)
            } else if log.contains("[WARN]") {
                Style::default().fg(Color::Yellow)
            } else if log.contains("[INFO]") {
                Style::default().fg(Color::Green)
            } else if log.contains("[DEBUG]") {
                Style::default().fg(Color::Blue)
            } else {
                Style::default().fg(Color::White)
            };
            
            ListItem::new(Line::from(Span::styled(log.as_str(), style)))
        })
        .collect();
    
    // Create log filter status text
    let filter_text = match app.log_filter {
        LogFilter::Debug => "Debug+",
        LogFilter::Info => "Info+",
        LogFilter::Warn => "Warn+",
        LogFilter::Error => "Error only",
        LogFilter::Custom => "Custom filter",
    };
    
    // Create log list
    let logs = List::new(log_items)
        .block(
            Block::default()
                .title(format!("Logs [{}]", filter_text))
                .borders(Borders::ALL)
                .border_style(
                    if app.active_block == ActiveBlock::LogView {
                        Style::default().fg(Color::Yellow)
                    } else {
                        Style::default().fg(Color::White)
                    }
                )
        )
        .highlight_style(Style::default().add_modifier(Modifier::BOLD));
    
    // Handle log scrolling
    let mut log_state = ListState::default();
    log_state.select(Some(app.log_scroll));
    
    f.render_stateful_widget(logs, area, &mut log_state);
}

/// Draw the status bar with enhanced information
fn draw_status_bar<B: Backend>(f: &mut Frame<B>, app: &mut App, area: Rect) {
    // Create the status indicators
    let status_style = if app.program_running {
        Style::default().fg(Color::Green)
    } else {
        Style::default().fg(Color::Red)
    };
    
    let program_status = if app.program_running { "Running" } else { "Stopped" };
    
    // Count active breakpoints
    let breakpoint_count = app.breakpoint_count;
    let breakpoint_style = if breakpoint_count > 0 {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default().fg(Color::Gray)
    };
    
    // Add function info if available
    let function_info = if let Some(func) = &app.current_function {
        func.to_string()
    } else {
        "No function".to_string()
    };
    
    // Add keyboard shortcuts based on context
    let help_text = match app.active_block {
        ActiveBlock::MainView => "[q]uit | [Tab]switch panel | [g]o | [b]reakpoint | [s]tep | [n]ext | [r]un",
        ActiveBlock::CommandInput => "[Esc]cancel | [Enter]submit",
        ActiveBlock::LogView => "[q]uit | [Tab]switch panel | [↑/↓]scroll logs",
    };
    
    let text = vec![
        Line::from(vec![
            Span::styled(format!("Status: {}", program_status), status_style),
            Span::raw(" | "),
            Span::styled(format!("BP: {}", breakpoint_count), breakpoint_style),
            Span::raw(" | "),
            Span::raw(format!("Func: {}", function_info)),
            Span::raw(" | "),
            Span::raw(format!("PID: {}", app.process_id.unwrap_or(0))),
        ]),
        Line::from(vec![
            Span::styled(help_text, Style::default().fg(Color::White)),
        ]),
    ];
    
    let paragraph = Paragraph::new(text)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .padding(Padding::new(1, 0, 0, 0))
        )
        .style(Style::default().fg(Color::White));
    
    f.render_widget(paragraph, area);
} 