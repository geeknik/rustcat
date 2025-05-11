#![allow(clippy::uninlined_format_args)]
#![allow(clippy::items_after_statements)]
#![allow(clippy::option_if_let_else)]
#![allow(clippy::must_use_candidate)]

use ratatui::{
    backend::Backend,
    layout::{Constraint, Direction, Layout, Rect, Alignment, Margin},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Padding, Tabs, Paragraph, BorderType, List, ListItem, ListState, Clear, Wrap},
    symbols,
    Frame,
};

use std::sync::mpsc;


use crate::tui::app::{App, View, ActiveBlock, LogFilter, UiMode};
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
    // Create main layout with 5 parts:
    // 1. Title bar with tabs (top)
    // 2. Main content area (middle)
    // 3. Log area (resizable, below main)
    // 4. Help bar (keyboard shortcuts)
    // 5. Status bar (bottom)
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([
            Constraint::Length(3),     // Title bar
            Constraint::Min(15),       // Main content
            Constraint::Length(7),     // Log view
            Constraint::Length(3),     // Help bar
            Constraint::Length(3),     // Status bar
        ])
        .split(f.size());

    // Draw title bar
    draw_title_bar(f, app, chunks[0]);
    
    // Draw main content area
    draw_main_area(f, app, chunks[1]);
    
    // Draw log area
    draw_log_area(f, app, chunks[2]);
    
    // Draw help bar
    draw_help_bar(f, app, chunks[3]);
    
    // Draw status bar
    draw_status_bar(f, app, chunks[4]);
    
    // Draw help overlay if in help mode
    if app.ui_mode == UiMode::HelpOverlay {
        draw_help_overlay(f, app);
    }
    
    // Draw context menu if active
    if app.ui_mode == UiMode::ContextMenu {
        if let Some(position) = app.context_menu_position {
            draw_context_menu(f, app, position);
        }
    }
}

/// Draw the title bar with tabs
fn draw_title_bar<B: Backend>(f: &mut Frame<B>, app: &App, area: Rect) {
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
fn draw_main_area<B: Backend>(f: &mut Frame<B>, app: &App, area: Rect) {
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
fn draw_log_area<B: Backend>(f: &mut Frame<B>, app: &App, area: Rect) {
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

/// Draw a help bar with context-sensitive keyboard shortcuts
fn draw_help_bar<B: Backend>(f: &mut Frame<B>, app: &App, area: Rect) {
    // Get context-sensitive key bindings based on current view and active block
    let help_text = match (app.current_view, app.active_block) {
        (_, ActiveBlock::CommandInput) => 
            "[Esc] Cancel | [↑/↓] History | [Enter] Execute | [Tab] Autocomplete",
            
        (_, ActiveBlock::LogView) => 
            "[↑/↓] Scroll | [PgUp/PgDn] Page | [Ctrl+F] Search | [Ctrl+N/P] Next/Prev | [Ctrl+L] Filter",
            
        (View::Code, _) => 
            "[F1] Help | [F3] Toggle Perf | [g] Go/Continue | [b] Breakpoint | [s] Step | [n] Next | [Space] Disassemble",
            
        (View::Memory, _) => 
            "[F1] Help | [F3] Toggle Perf | [Enter] Go to Address | [Tab] Cycle View | [+/-] Zoom | [m] Format",
            
        (View::Registers, _) => 
            "[F1] Help | [F3] Toggle Perf | [Tab] Group | [↑/↓] Select | [Enter] Edit | [r] Refresh",
            
        (View::Stack, _) => 
            "[F1] Help | [F3] Toggle Perf | [↑/↓] Select Frame | [Enter] Jump to Frame | [Space] Show Variables",
            
        (View::Threads, _) => 
            "[F1] Help | [F3] Toggle Perf | [↑/↓] Select | [Enter] Switch | [Space] Suspend/Resume | [k] Kill",
            
        (View::Trace, _) => 
            "[F1] Help | [F3] Toggle Perf | [↑/↓] Navigate | [c] Clear | [f] Filter | [s] Save | [Space] Collapse/Expand",
            
        (View::Variables, _) => 
            "[F1] Help | [F3] Toggle Perf | [↑/↓] Select | [Enter] Expand | [w] Watch | [e] Edit | [Space] Show Memory",
            
        (View::Command, _) => 
            "[F1] Help | [F3] Toggle Perf | [↑/↓] History | [Tab] Complete | [Ctrl+C] Clear | [Enter] Execute",
    };
    
    // Create the paragraph widget
    let help_paragraph = Paragraph::new(Line::from(vec![
        Span::styled(help_text, Style::default().fg(Color::White))
    ]))
    .block(Block::default().borders(Borders::ALL).title("Keyboard Shortcuts"))
    .alignment(Alignment::Center);
    
    // Render the help bar
    f.render_widget(help_paragraph, area);
}

/// Draw the status bar
fn draw_status_bar<B: Backend>(f: &mut Frame<B>, app: &App, area: Rect) {
    // Create a layout with two columns for status information
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(70), // Left side (main status)
            Constraint::Percentage(30), // Right side (performance metrics)
        ])
        .split(area);
    
    // Prepare the left side with debugger status
    let status = format!(
        "Status: {} | Process: {} | Function: {} | Breakpoints: {}",
        if app.program_running { "Running" } else { "Stopped" },
        app.process_id.map_or_else(|| "N/A".to_string(), |pid| pid.to_string()),
        app.current_function.as_deref().unwrap_or("N/A"),
        app.breakpoint_count
    );
    
    let status_paragraph = Paragraph::new(Line::from(vec![
        Span::styled(status, Style::default().fg(Color::White))
    ]))
    .block(Block::default().borders(Borders::ALL).padding(Padding::new(1, 0, 0, 0)))
    .alignment(Alignment::Left);
    
    // Draw the left status bar
    f.render_widget(status_paragraph, chunks[0]);
    
    // Prepare the right side with performance metrics (if enabled)
    if app.show_performance {
        let (avg_time, max_time, is_slow) = app.get_performance_metrics();
        
        // Convert durations to milliseconds with 2 decimal places
        let avg_ms = avg_time.as_secs_f64() * 1000.0;
        let max_ms = max_time.as_secs_f64() * 1000.0;
        
        // Choose color based on performance
        let perf_color = if is_slow { 
            Color::Red 
        } else if avg_ms > 5.0 { 
            Color::Yellow 
        } else { 
            Color::Green 
        };
        
        let perf_text = format!("UI: {:.2}ms (max: {:.2}ms)", avg_ms, max_ms);
        
        let perf_paragraph = Paragraph::new(Line::from(vec![
            Span::styled(perf_text, Style::default().fg(perf_color))
        ]))
        .block(Block::default().borders(Borders::ALL).padding(Padding::new(1, 0, 0, 0)))
        .alignment(Alignment::Right);
        
        // Draw the right status bar
        f.render_widget(perf_paragraph, chunks[1]);
    }
}

/// Draw a help overlay with detailed usage instructions
fn draw_help_overlay<B: Backend>(f: &mut Frame<B>, app: &App) {
    // Create a centered window for the help overlay
    let area = centered_rect(80, 60, f.size());
    
    // Define help content based on current view
    let title = format!("Help for {} View", view_to_string(app.current_view));
    
    let help_content: Vec<String> = match app.current_view {
        View::Code => vec![
            "CODE VIEW SHORTCUTS:".to_string(),
            "  F1: Toggle this help overlay".to_string(),
            "  F3: Toggle performance metrics".to_string(),
            "  1-8: Switch between views".to_string(),
            "  c: Switch to code view".to_string(),
            "  b: Set/clear breakpoint at cursor".to_string(),
            "  g: Continue execution".to_string(),
            "  n: Step over".to_string(),
            "  s: Step into".to_string(),
            "  f: Step out".to_string(),
            "  Space: Toggle disassembly at cursor".to_string(),
            String::new(),
            "DEBUGGER COMMANDS:".to_string(),
            "  break <location>: Set breakpoint".to_string(),
            "  continue: Resume execution".to_string(),
            "  step: Step into".to_string(),
            "  next: Step over".to_string(),
            "  finish: Step out".to_string(),
            "  run: Start execution".to_string(),
            "  quit: Exit debugger".to_string(),
        ],
        View::Memory => vec![
            "MEMORY VIEW SHORTCUTS:".to_string(),
            "  F1: Toggle this help overlay".to_string(),
            "  F3: Toggle performance metrics".to_string(),
            "  1-8: Switch between views".to_string(),
            "  m: Switch to memory view".to_string(),
            "  Up/Down: Scroll through memory".to_string(),
            "  Left/Right: Change columns".to_string(),
            "  +/-: Zoom in/out".to_string(),
            "  Tab: Cycle display format (Hex/ASCII/Int)".to_string(),
            "  Enter: Go to specific address".to_string(),
            "  Space: Mark memory region".to_string(),
            String::new(),
            "COMMANDS:".to_string(),
            "  memory <addr> <size>: View memory at address".to_string(),
            "  x/<size><format> <addr>: Examine memory".to_string(),
            "  watch <addr>: Set watchpoint".to_string(),
        ],
        View::Registers => vec![
            "REGISTER VIEW SHORTCUTS:".to_string(),
            "  F1: Toggle this help overlay".to_string(),
            "  F3: Toggle performance metrics".to_string(),
            "  1-8: Switch between views".to_string(),
            "  r: Switch to register view".to_string(),
            "  Tab: Cycle register groups (General/Special/SIMD)".to_string(),
            "  Up/Down: Select register".to_string(),
            "  Enter: Edit selected register".to_string(),
            "  Space: Show memory at register address".to_string(),
            String::new(),
            "COMMANDS:".to_string(),
            "  registers: Show registers".to_string(),
            "  set $reg=value: Set register value".to_string(),
        ],
        _ => vec![
            format!("{} VIEW HELP", view_to_string(app.current_view).to_uppercase()),
            "  F1: Toggle this help overlay".to_string(),
            "  F3: Toggle performance metrics".to_string(),
            "  1-8: Switch between views".to_string(),
            "  Tab: Switch focus between panels".to_string(),
            "  q: Quit application".to_string(),
            String::new(),
            "Press F1 again to close this help overlay".to_string()
        ],
    };
    
    // Create the help text
    let help_text: Vec<Line> = help_content.into_iter()
        .map(|line| {
            if line.starts_with("  ") {
                // Indent means it's a detail, use normal color
                Line::from(Span::styled(line, Style::default().fg(Color::White)))
            } else if line.is_empty() {
                // Empty line for spacing
                Line::from("")
            } else {
                // Heading, use bright color
                Line::from(Span::styled(line, Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)))
            }
        })
        .collect();
    
    // Create the overlay
    let help_paragraph = Paragraph::new(help_text)
        .block(Block::default()
            .title(title)
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded))
        .alignment(Alignment::Left)
        .wrap(Wrap { trim: true });
    
    // Create a clear background
    let background = Block::default()
        .style(Style::default().bg(Color::Black).fg(Color::White));
    
    f.render_widget(Clear, area); // Clear the area first
    f.render_widget(background, area); // Render semi-transparent background
    f.render_widget(help_paragraph, area.inner(&Margin { vertical: 2, horizontal: 4 })); // Render help with margins
}

/// Helper function to convert View enum to string
fn view_to_string(view: View) -> String {
    match view {
        View::Code => "Code".to_string(),
        View::Memory => "Memory".to_string(),
        View::Registers => "Registers".to_string(),
        View::Stack => "Stack".to_string(),
        View::Threads => "Threads".to_string(),
        View::Command => "Command".to_string(),
        View::Trace => "Trace".to_string(),
        View::Variables => "Variables".to_string(),
    }
}

/// Helper function to create a centered rect
fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}

/// Draw context menu at a specific position
fn draw_context_menu<B: Backend>(f: &mut Frame<B>, app: &App, position: (u16, u16)) {
    // Create menu items based on current menu
    let items: Vec<String> = app.context_menu_items.iter()
        .map(|action| {
            match action {
                crate::tui::app::ContextMenuAction::SetBreakpoint => "Set Breakpoint".to_string(),
                crate::tui::app::ContextMenuAction::ClearBreakpoint => "Clear Breakpoint".to_string(),
                crate::tui::app::ContextMenuAction::RunToCursor => "Run To Cursor".to_string(),
                crate::tui::app::ContextMenuAction::Copy => "Copy".to_string(),
                crate::tui::app::ContextMenuAction::ViewMemory(_) => "View Memory".to_string(),
                crate::tui::app::ContextMenuAction::SaveToFile => "Save To File".to_string(),
                crate::tui::app::ContextMenuAction::Submenu(name, _) => format!("{} ▶", name),
            }
        })
        .collect();
    
    // Determine menu width based on longest item
    let width = items.iter()
        .map(|s| s.len() as u16)
        .max()
        .unwrap_or(15)
        .max(15) + 4; // Minimum width of 15 plus padding
    
    let height = (items.len() as u16) + 2; // +2 for borders
    
    // Ensure the menu stays within the terminal bounds
    let (mut x, mut y) = position;
    let term_size = f.size();
    
    if x + width > term_size.width {
        x = term_size.width - width - 1;
    }
    
    if y + height > term_size.height {
        y = term_size.height - height - 1;
    }
    
    let menu_area = Rect::new(x, y, width, height);
    
    // Create the menu
    let menu_items: Vec<Line> = items.iter()
        .enumerate()
        .map(|(i, item)| {
            let style = if i == app.context_menu_selected {
                Style::default().fg(Color::Black).bg(Color::White)
            } else {
                Style::default().fg(Color::White)
            };
            
            Line::from(Span::styled(item, style))
        })
        .collect();
    
    let menu = Paragraph::new(menu_items)
        .block(Block::default().borders(Borders::ALL).border_type(BorderType::Plain))
        .style(Style::default().bg(Color::DarkGray));
    
    // Render the menu
    f.render_widget(Clear, menu_area);
    f.render_widget(menu, menu_area);
} 