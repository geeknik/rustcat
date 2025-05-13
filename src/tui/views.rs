use ratatui::{
    backend::Backend,
    layout::{Rect, Alignment, Layout, Constraint, Direction},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph, Table, Row, Cell, Tabs, ListState, Wrap},
    symbols,
    Frame,
};

use crate::tui::app::{App, View, ActiveBlock};
use crate::debugger::threads::{ThreadState};
use crate::debugger::registers::{RegisterGroup, Register};
use crate::debugger::core::Debugger;
use crate::debugger::breakpoint::Watchpoint;

/// View for the code display
pub struct CodeView;

impl Default for CodeView {
    fn default() -> Self {
        Self::new()
    }
}

impl CodeView {
    pub fn new() -> Self {
        Self
    }

    pub fn render<B: Backend>(&self, f: &mut Frame<B>, area: Rect) {
        let text = vec![
            Line::from("Code View - Source and Assembly"),
            Line::from("0x100000f24: mov    rax, qword ptr [rip + 0x7e]"),
            Line::from("0x100000f2b: mov    qword ptr [rsp], rax"),
            Line::from("0x100000f2f: lea    rdi, [rip + 0x8a]"),
        ];
        
        let paragraph = Paragraph::new(text)
            .block(Block::default().borders(Borders::ALL).title("Source & Assembly"))
            .style(Style::default().fg(Color::White));
        
        f.render_widget(paragraph, area);
    }
}

/// View for memory display
pub struct MemoryView;

impl Default for MemoryView {
    fn default() -> Self {
        Self::new()
    }
}

impl MemoryView {
    pub fn new() -> Self {
        Self
    }

    #[allow(dead_code)]
    pub fn render<B: Backend>(&self, f: &mut Frame<B>, area: Rect) {
        let text = vec![
            Line::from("Memory View - Hex and ASCII"),
            Line::from("0x100000000: 48 89 45 f8 48 8d 3d 8a 00 00 00 e8 5e 00 00 00  |H.E.H.=.....^...|"),
            Line::from("0x100000010: 48 89 45 f0 48 8b 45 f0 48 89 45 e8 c7 45 e4 00  |H.E.H.E.H.E..E..|"),
            Line::from("0x100000020: 00 00 00 c7 45 e0 00 00 00 00 8b 45 e4 3b 45 e0  |....E......E.;E.|"),
        ];
        
        let paragraph = Paragraph::new(text)
            .block(Block::default().borders(Borders::ALL).title("Memory"))
            .style(Style::default().fg(Color::White));
        
        f.render_widget(paragraph, area);
    }
}

/// View for registers
pub struct RegistersView;

impl Default for RegistersView {
    fn default() -> Self {
        Self::new()
    }
}

impl RegistersView {
    pub fn new() -> Self {
        Self
    }

    #[allow(dead_code)]
    pub fn render<B: Backend>(&self, f: &mut Frame<B>, area: Rect) {
        let registers = [
            "rax: 0x0000000100000f24",
            "rbx: 0x0000000000000000",
            "rcx: 0x00007ff7bfeff680",
            "rdx: 0x00007ff7bfeff698",
            "rsi: 0x00007ff7bfeff688",
            "rdi: 0x0000000000000001",
            "rbp: 0x00007ff7bfeff6a0",
            "rsp: 0x00007ff7bfeff648",
            "r8:  0x0000000000000000",
            "r9:  0x0000000000000000"
        ];
        
        let items: Vec<ListItem> = registers
            .iter()
            .map(|r| ListItem::new(Line::from(vec![Span::styled(*r, Style::default().fg(Color::White))])))
            .collect();
        
        let list = List::new(items)
            .block(Block::default().borders(Borders::ALL).title("Registers"))
            .style(Style::default().fg(Color::White))
            .highlight_style(Style::default().add_modifier(Modifier::BOLD))
            .highlight_symbol("> ");
        
        f.render_widget(list, area);
    }
}

/// View for the stack trace
pub struct StackView;

impl Default for StackView {
    fn default() -> Self {
        Self::new()
    }
}

impl StackView {
    pub fn new() -> Self {
        Self
    }

    #[allow(dead_code)]
    pub fn render<B: Backend>(&self, f: &mut Frame<B>, area: Rect) {
        let stack_frames = [
            "#0 0x0000000100000f24 main()",
            "#1 0x00007ff7bfc01014 start + 0"
        ];
        
        let items: Vec<ListItem> = stack_frames
            .iter()
            .map(|s| ListItem::new(Line::from(vec![Span::styled(*s, Style::default().fg(Color::White))])))
            .collect();
        
        let list = List::new(items)
            .block(Block::default().borders(Borders::ALL).title("Stack Trace"))
            .style(Style::default().fg(Color::White))
            .highlight_style(Style::default().add_modifier(Modifier::BOLD))
            .highlight_symbol("> ");
        
        f.render_widget(list, area);
    }
}

/// View for threads
pub struct ThreadsView;

impl Default for ThreadsView {
    fn default() -> Self {
        Self::new()
    }
}

impl ThreadsView {
    pub fn new() -> Self {
        Self
    }

    #[allow(dead_code)]
    pub fn render<B: Backend>(&self, f: &mut Frame<B>, area: Rect) {
        let threads = [
            "Thread 0x1103 (main)",
            "Thread 0x1503 (worker)",
            "Thread 0x1703 (worker)"
        ];
        
        let items: Vec<ListItem> = threads
            .iter()
            .map(|t| ListItem::new(Line::from(vec![Span::styled(*t, Style::default().fg(Color::White))])))
            .collect();
        
        let list = List::new(items)
            .block(Block::default().borders(Borders::ALL).title("Threads"))
            .style(Style::default().fg(Color::White))
            .highlight_style(Style::default().add_modifier(Modifier::BOLD))
            .highlight_symbol("> ");
        
        f.render_widget(list, area);
    }
}

/// View for command input
pub struct CommandView;

impl Default for CommandView {
    fn default() -> Self {
        Self::new()
    }
}

impl CommandView {
    pub fn new() -> Self {
        Self
    }

    pub fn render<B: Backend>(&self, f: &mut Frame<B>, area: Rect, app: &App) {
        let block = Block::default()
            .title(Line::from(Span::styled(
                "Command",
                Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
            )))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(if app.current_view == View::Command {
                Color::Green
            } else {
                Color::Gray
            }));
        
        let inner_area = block.inner(area);
        f.render_widget(block, area);
        
        // Create a list of command output and history to display
        let mut items = Vec::new();
        
        // Display the expression evaluation result if available
        if let Some(result) = &app.expression_result {
            items.push(ListItem::new(Line::from(vec![
                Span::styled("Result: ", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
                Span::styled(result, Style::default().fg(Color::LightGreen)),
            ])));
            
            // Add a separator
            items.push(ListItem::new(Line::from(vec![
                Span::styled("─".repeat(inner_area.width as usize), Style::default().fg(Color::DarkGray))
            ])));
        }
        
        // Add command history if available
        if !app.command_history.is_empty() {
            items.push(ListItem::new(Line::from(vec![
                Span::styled("Command History", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))
            ])));
            
            // Add the most recent commands (up to 10)
            let num_items = std::cmp::min(app.command_history.len(), 10);
            let start_idx = app.command_history.len().saturating_sub(num_items);
            
            for i in start_idx..app.command_history.len() {
                let cmd = &app.command_history[i];
                items.push(ListItem::new(Line::from(vec![
                    Span::styled(format!("{}: ", i - start_idx + 1), Style::default().fg(Color::DarkGray)),
                    Span::styled(cmd, Style::default().fg(Color::White)),
                ])));
            }
        }
        
        // Add command input display
        let _command_prompt = if app.active_block == ActiveBlock::CommandInput {
            format!("> {}", app.command_input)
        } else {
            String::from("> ")
        };
        
        // If there are no items, at least show the prompt
        if items.is_empty() {
            items.push(ListItem::new(Line::from(vec![
                Span::styled("Type a command and press Enter", Style::default().fg(Color::Gray)),
            ])));
        }
        
        let list = List::new(items)
            .block(Block::default())
            .highlight_style(Style::default().bg(Color::DarkGray))
            .highlight_symbol("> ");
        
        f.render_widget(list, inner_area);
        
        // Display the command prompt at the bottom if we're in command input mode
        if app.active_block == ActiveBlock::CommandInput {
            let prompt_layout = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(inner_area.height.saturating_sub(1)),
                    Constraint::Length(1),
                ])
                .split(inner_area);
            
            let prompt = Paragraph::new(Line::from(vec![
                Span::styled("> ", Style::default().fg(Color::Green)),
                Span::styled(&app.command_input, Style::default().fg(Color::White)),
            ]))
            .style(Style::default());
            
            f.render_widget(prompt, prompt_layout[1]);
        }
    }
}

/// Draw memory view in the specified area
pub fn draw_memory_view<B: Backend>(
    f: &mut Frame<B>,
    app: &App,
    area: Rect,
    memory_data: Option<&Vec<u8>>,
    memory_address: u64,
) {
    let title = Line::from(Span::styled(
        "Memory Viewer",
        Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
    ));
    
    let block = Block::default()
        .borders(Borders::ALL)
        .title(title.alignment(Alignment::Center));

    let _inner_area = block.inner(area);
    
    if let Some(data) = memory_data {
        // Get any watchpoints that might be covering this memory region
        let memory_end = memory_address + data.len() as u64;
        let active_watchpoints = get_watchpoints_for_range(app, memory_address, memory_end);
        
        let bytes_per_row = 16;
        let mut rows = Vec::new();
        
        // Add watchpoint legend at the top if any watchpoints are active
        if !active_watchpoints.is_empty() {
            rows.push(Line::from(Span::styled(
                "Watchpoints in this region:",
                Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
            )));
            
            for wp in &active_watchpoints {
                // Different colors based on watchpoint type
                let wp_type_style = match wp.watchpoint_type() {
                    crate::platform::WatchpointType::Read => 
                        Style::default().fg(Color::Blue).add_modifier(Modifier::BOLD),
                    crate::platform::WatchpointType::Write => 
                        Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                    crate::platform::WatchpointType::ReadWrite => 
                        Style::default().fg(Color::Magenta).add_modifier(Modifier::BOLD),
                    crate::platform::WatchpointType::Conditional => 
                        Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
                    crate::platform::WatchpointType::Logging => 
                        Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
                };
                
                let wp_type_text = match wp.watchpoint_type() {
                    crate::platform::WatchpointType::Read => "READ",
                    crate::platform::WatchpointType::Write => "WRITE",
                    crate::platform::WatchpointType::ReadWrite => "READ/WRITE",
                    crate::platform::WatchpointType::Conditional => "CONDITIONAL",
                    crate::platform::WatchpointType::Logging => "LOGGING",
                };
                
                rows.push(Line::from(vec![
                    Span::raw("  "),
                    Span::styled(
                        format!("{} watchpoint at 0x{:x} (size: {})", 
                                wp_type_text, wp.address(), wp.size()),
                        wp_type_style
                    ),
                ]));
            }
            
            // Add separator after watchpoint list
            rows.push(Line::from(Span::raw("──────────────────────────────────────────────────────")));
        }
        
        // Process each row of memory data
        for (i, chunk) in data.chunks(bytes_per_row).enumerate() {
            // ... existing code for generating row_address, hex_text, ascii_text ...
            
            // Check if any address in this row has a watchpoint
            let row_address = memory_address + (i * bytes_per_row) as u64;
            let _row_end_address = row_address + chunk.len() as u64;
            
            // Create arrays to track which bytes are covered by which watchpoint types
            let mut byte_watchpoints = vec![None; chunk.len()];
            
            // Check each byte for watchpoint coverage
            for wp in &active_watchpoints {
                let wp_start = wp.address();
                let wp_end = wp_start + wp.size() as u64;
                
                // Find bytes in this row that are covered by this watchpoint
                for (byte_idx, _) in chunk.iter().enumerate() {
                    let byte_addr = row_address + byte_idx as u64;
                    if byte_addr >= wp_start && byte_addr < wp_end {
                        byte_watchpoints[byte_idx] = Some(wp.watchpoint_type());
                    }
                }
            }
            
            // Generate hex representation with per-byte watchpoint highlighting
            let mut hex_text = String::new();
            let mut hex_spans = Vec::new();
            
            for (byte_idx, byte) in chunk.iter().enumerate() {
                let byte_text = format!("{:02x}", byte);
                
                if let Some(wp_type) = byte_watchpoints[byte_idx] {
                    // Style based on watchpoint type
                    let style = match wp_type {
                        crate::platform::WatchpointType::Read => 
                            Style::default().fg(Color::Blue).add_modifier(Modifier::BOLD),
                        crate::platform::WatchpointType::Write => 
                            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                        crate::platform::WatchpointType::ReadWrite => 
                            Style::default().fg(Color::Magenta).add_modifier(Modifier::BOLD),
                        crate::platform::WatchpointType::Conditional => 
                            Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
                        crate::platform::WatchpointType::Logging => 
                            Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
                    };
                    
                    hex_spans.push(Span::styled(byte_text.clone(), style));
                } else {
                    hex_spans.push(Span::styled(byte_text.clone(), Style::default().fg(Color::White)));
                }
                
                if byte_idx < chunk.len() - 1 {
                    hex_spans.push(Span::raw(" "));
                }
                hex_text.push_str(&format!("{:02x} ", byte));
            }
            
            // Trim trailing space
            if !hex_text.is_empty() {
                hex_text.pop();
            }
            
            // Generate ASCII representation
            let mut ascii_text = String::new();
            let mut ascii_spans = Vec::new();
            
            for (byte_idx, &byte) in chunk.iter().enumerate() {
                let c = if (32..=126).contains(&byte) {
                    byte as char
                } else {
                    '.'
                };
                
                if let Some(wp_type) = byte_watchpoints[byte_idx] {
                    // Style based on watchpoint type
                    let style = match wp_type {
                        crate::platform::WatchpointType::Read => 
                            Style::default().fg(Color::Blue).add_modifier(Modifier::BOLD),
                        crate::platform::WatchpointType::Write => 
                            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                        crate::platform::WatchpointType::ReadWrite => 
                            Style::default().fg(Color::Magenta).add_modifier(Modifier::BOLD),
                        crate::platform::WatchpointType::Conditional => 
                            Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
                        crate::platform::WatchpointType::Logging => 
                            Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
                    };
                    
                    ascii_spans.push(Span::styled(c.to_string(), style));
                } else {
                    ascii_spans.push(Span::styled(c.to_string(), Style::default().fg(Color::Cyan)));
                }
                
                ascii_text.push(c);
            }
            
            // Build row with all spans
            let mut row_spans = Vec::new();
            
            // Address (yellow)
            row_spans.push(Span::styled(
                format!("{:016x}", row_address),
                Style::default().fg(Color::Yellow)
            ));
            
            // Separator
            row_spans.push(Span::raw(" | "));
            
            // Hex bytes with watchpoint highlighting
            row_spans.extend(hex_spans);
            
            // Separator
            row_spans.push(Span::raw(" | "));
            
            // ASCII with watchpoint highlighting
            row_spans.extend(ascii_spans);
            
            // Add this row to our rows collection
            rows.push(Line::from(row_spans));
        }
        
        // Add a legend at the bottom
        rows.push(Line::from(Span::raw(""))); // Empty line as separator
        rows.push(Line::from(vec![
            Span::styled("READ", Style::default().fg(Color::Blue).add_modifier(Modifier::BOLD)),
            Span::raw(" "),
            Span::styled("WRITE", Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)),
            Span::raw(" "),
            Span::styled("READ/WRITE", Style::default().fg(Color::Magenta).add_modifier(Modifier::BOLD)),
            Span::raw(" watchpoints")
        ]));

        let paragraph = Paragraph::new(rows)
            .block(block)
            .wrap(Wrap { trim: true });

        f.render_widget(paragraph, area);
    } else {
        // No data, display a message
        let text = vec![Line::from(vec![
            Span::raw("No memory data available. Use 'memory <address> <size>' to view memory."),
        ])];

        let paragraph = Paragraph::new(text)
            .block(block)
            .wrap(Wrap { trim: true });

        f.render_widget(paragraph, area);
    }
}

/// Draw thread view in the specified area
pub fn draw_thread_view<B: Backend>(
    f: &mut Frame<B>,
    app: &App,
    area: Rect,
) {
    let block = Block::default()
        .title(Line::from(Span::styled(
            "Threads",
            Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
        )))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(if app.current_view == View::Threads {
            Color::Green
        } else {
            Color::Gray
        }));
    
    let inner_area = block.inner(area);
    f.render_widget(block, area);
    
    // Get thread information from the debugger
    let debugger = app.get_debugger();
    
    if let Ok(debugger) = debugger.lock() {
        if let Some(thread_manager) = debugger.get_thread_manager() {
            let current_thread_id = thread_manager.current_thread_id();
            
            // Create table headers
            let header = Row::new(vec![
                "ID", "Name", "State", "Location", "PC", "SP"
            ].into_iter().map(|h| Cell::from(h).style(Style::default().fg(Color::Yellow))))
            .style(Style::default().fg(Color::Yellow));
            
            // Create rows for each thread
            let rows = thread_manager.get_all_threads().iter().map(|(&tid, thread)| {
                // Get location information
                let location = if let Some(frame) = thread.current_frame() {
                    if let (Some(file), Some(line)) = (&frame.source_file, frame.line) {
                        format!("{}:{}", file, line)
                    } else if let Some(function) = &frame.function {
                        function.clone()
                    } else {
                        "Unknown".to_string()
                    }
                } else {
                    "Unknown".to_string()
                };
                
                // Format PC and SP
                let pc = thread.registers()
                    .and_then(super::super::debugger::registers::Registers::get_program_counter)
                    .map_or("N/A".to_string(), |v| format!("0x{:x}", v));
                
                let sp = thread.registers()
                    .and_then(super::super::debugger::registers::Registers::get_stack_pointer)
                    .map_or("N/A".to_string(), |v| format!("0x{:x}", v));
                
                // Create row style based on thread state
                let style = if Some(tid) == current_thread_id {
                    Style::default().fg(Color::Green)
                } else {
                    match thread.state() {
                        ThreadState::Running => Style::default().fg(Color::Blue),
                        ThreadState::Stopped | ThreadState::AtBreakpoint => Style::default().fg(Color::Yellow),
                        ThreadState::Suspended => Style::default().fg(Color::DarkGray),
                        ThreadState::Exited(_) => Style::default().fg(Color::Red),
                        _ => Style::default(),
                    }
                };
                
                // Create the row
                Row::new(vec![
                    tid.to_string(), 
                    thread.name().unwrap_or("N/A").to_string(),
                    thread.state().description(),
                    location,
                    pc,
                    sp,
                ]).style(style)
            }).collect::<Vec<Row>>();
            
            // Create the table
            let table = Table::new(rows)
                .header(header)
                .block(Block::default())
                .highlight_style(Style::default().add_modifier(Modifier::BOLD))
                .widths(&[
                    ratatui::layout::Constraint::Length(6),  // ID
                    ratatui::layout::Constraint::Length(15), // Name
                    ratatui::layout::Constraint::Length(15), // State
                    ratatui::layout::Constraint::Min(20),    // Location
                    ratatui::layout::Constraint::Length(12), // PC
                    ratatui::layout::Constraint::Length(12), // SP
                ]);
            
            f.render_widget(table, inner_area);
        } else {
            // No thread manager or no threads
            let text = if debugger.get_state() == crate::debugger::core::DebuggerState::Running {
                "No thread information available."
            } else {
                "No program is running."
            };
            
            let paragraph = Paragraph::new(text)
                .alignment(Alignment::Center)
                .style(Style::default().fg(Color::Gray));
            
            f.render_widget(paragraph, inner_area);
        }
    } else {
        // Failed to lock debugger
        let paragraph = Paragraph::new("Failed to access debugger.")
            .alignment(Alignment::Center)
            .style(Style::default().fg(Color::Red));
        
        f.render_widget(paragraph, inner_area);
    }
}

/// Draw call stack view in the specified area
pub fn draw_call_stack_view<B: Backend>(
    f: &mut Frame<B>,
    app: &App,
    area: Rect,
) {
    let block = Block::default()
        .title(Line::from(Span::styled(
            "Call Stack",
            Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
        )))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(if app.current_view == View::Stack {
            Color::Green
        } else {
            Color::Gray
        }));
    
    let inner_area = block.inner(area);
    f.render_widget(block, area);
    
    // Get call stack from the debugger
    let debugger = app.get_debugger();
    
    if let Ok(debugger) = debugger.lock() {
        if let Some(thread_manager) = debugger.get_thread_manager() {
            if let Some(thread) = thread_manager.current_thread() {
                let call_stack = thread.call_stack();
                
                if !call_stack.is_empty() {
                    // Create items for the call stack
                    let items: Vec<ListItem> = call_stack.iter()
                        .map(|frame| {
                            let desc = frame.description();
                            ListItem::new(Line::from(vec![
                                Span::styled(desc, if frame.number == 0 {
                                    Style::default().fg(Color::Green) // Current frame
                                } else {
                                    Style::default()
                                })
                            ]))
                        })
                        .collect();
                    
                    let list = List::new(items)
                        .block(Block::default())
                        .highlight_style(Style::default().add_modifier(Modifier::BOLD));
                    
                    f.render_widget(list, inner_area);
                    return;
                }
            }
        }
        
        // No thread, call stack, or frames
        let text = if debugger.get_state() == crate::debugger::core::DebuggerState::Running {
            "No call stack information available."
        } else {
            "No program is running."
        };
        
        let paragraph = Paragraph::new(text)
            .alignment(Alignment::Center)
            .style(Style::default().fg(Color::Gray));
        
        f.render_widget(paragraph, inner_area);
    } else {
        // Failed to lock debugger
        let paragraph = Paragraph::new("Failed to access debugger.")
            .alignment(Alignment::Center)
            .style(Style::default().fg(Color::Red));
        
        f.render_widget(paragraph, inner_area);
    }
}

/// Draw the registers view
pub fn draw_registers_view<B: Backend>(f: &mut Frame<B>, app: &App, area: Rect) {
    // Get register values from the app
    let registers = app.get_registers();
    
    // Create a layout with tabs for register groups
    let tabs_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),     // Tabs
            Constraint::Min(5),        // Register content
        ])
        .split(area);
    
    // Create tabs for register groups
    let titles = vec![
        Line::from(Span::styled("General", 
            if app.register_group_index == 0 { 
                Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)
            } else { 
                Style::default()
            }
        )),
        Line::from(Span::styled("Special", 
            if app.register_group_index == 1 { 
                Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)
            } else { 
                Style::default()
            }
        )),
        Line::from(Span::styled("Vector", 
            if app.register_group_index == 2 { 
                Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)
            } else { 
                Style::default()
            }
        )),
    ];
    
    let register_tabs = Tabs::new(titles.into_iter().collect::<Vec<_>>())
        .block(Block::default().borders(Borders::ALL).title("Register Groups"))
        .divider(symbols::line::VERTICAL)
        .highlight_style(Style::default().fg(Color::Yellow))
        .select(app.register_group_index);
    
    f.render_widget(register_tabs, tabs_layout[0]);
    
    // Get the selected group
    let group = match app.register_group_index {
        0 => RegisterGroup::General,
        1 => RegisterGroup::Special,
        2 => RegisterGroup::Vector,
        _ => RegisterGroup::General,
    };
    
    // Get registers for the selected group
    let mut register_items = Vec::new();
    
    if let Some(registers) = registers {
        let regs = registers.get_registers_by_group(group);
        
        for (reg, value) in regs {
            let value_text = match value {
                Some(val) => format!("0x{:016x}", val),
                None => "N/A".to_string(),
            };
            
            let abi_info = match reg.abi_name() {
                Some(name) => format!("({})", name),
                None => String::new(),
            };
            
            let style = if registers.is_dirty(reg) {
                Style::default().fg(Color::Yellow)
            } else {
                Style::default()
            };
            
            register_items.push(
                ListItem::new(Line::from(vec![
                    Span::styled(format!("{:<5}", reg.display_name()), style.add_modifier(Modifier::BOLD)),
                    Span::raw(" "),
                    Span::styled(value_text, style),
                    Span::raw(" "),
                    Span::styled(abi_info, Style::default().fg(Color::Gray)),
                ]))
            );
        }
    } else {
        // No register data available
        register_items.push(
            ListItem::new(Line::from(vec![
                Span::styled("No register data available", Style::default().fg(Color::Red)),
            ]))
        );
    }
    
    // Create scroll state
    let mut register_list_state = ListState::default();
    register_list_state.select(app.register_selection_index);
    
    // Create the register list
    let register_list = List::new(register_items)
        .block(
            Block::default()
                .title(format!("{} Registers", group))
                .borders(Borders::ALL)
                .border_style(
                    Style::default().fg(Color::White)
                )
        )
        .highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .add_modifier(Modifier::BOLD)
        );
    
    f.render_stateful_widget(register_list, tabs_layout[1], &mut register_list_state);
}

/// A view that displays disassembled code
pub struct DisassemblyView;

impl Default for DisassemblyView {
    fn default() -> Self {
        Self::new()
    }
}

impl DisassemblyView {
    pub fn new() -> Self {
        Self {}
    }
    
    #[allow(dead_code)]
    pub fn render<B: Backend>(&self, f: &mut Frame<B>, area: Rect, debugger: &Debugger, _current_address: Option<u64>, selected_index: Option<usize>) {
        // Create a block for the view
        let block = Block::default()
            .title("Disassembly")
            .borders(Borders::ALL)
            .style(Style::default().fg(Color::White));
        
        let inner_area = block.inner(area);
        f.render_widget(block, area);
        
        // Get current program counter
        if let Ok(registers) = debugger.get_registers() {
            if let Some(pc) = registers.get(Register::Pc) {
                // How many instructions to display (based on height)
                let count = inner_area.height as usize;
                
                // Try to put the current instruction in the middle
                let context_before = count / 2;
                let context_after = count - context_before - 1;
                
                // Get disassembly with context
                if let Ok(instructions) = debugger.get_disassembly_context(pc, context_before, context_after) {
                    // Find the index of the current instruction
                    let _current_idx = instructions.iter().position(|ins| ins.address == pc).unwrap_or_default();
                    
                    // Convert instructions to ListItems
                    let items: Vec<ListItem> = instructions.iter().enumerate().map(|(idx, ins)| {
                        // Check if this is the current instruction or selected
                        let is_current = ins.address == pc;
                        let is_selected = selected_index == Some(idx);
                        
                        // Style based on whether it's current or selected
                        let style = if is_current && is_selected {
                            Style::default().fg(Color::Black).bg(Color::Yellow)
                        } else if is_current {
                            Style::default().fg(Color::Yellow)
                        } else if is_selected {
                            Style::default().fg(Color::Blue)
                        } else {
                            Style::default().fg(Color::Gray)
                        };
                        
                        // Format the instruction line
                        let line = format!(
                            "{:#016x}: {:12} {}", 
                            ins.address, 
                            ins.hex_bytes(), 
                            ins.text
                        );
                        
                        ListItem::new(Line::from(vec![Span::styled(
                            line,
                            style,
                        )]))
                    }).collect();
                    
                    // Create and render the list
                    let list = List::new(items)
                        .highlight_symbol(">> ")
                        .style(Style::default().fg(Color::White));
                    
                    f.render_widget(list, inner_area);
                } else {
                    // Show error message if disassembly fails
                    let message = Paragraph::new("Could not disassemble at this address")
                        .style(Style::default().fg(Color::Red))
                        .wrap(Wrap { trim: true });
                    f.render_widget(message, inner_area);
                }
            }
        } else {
            // Show message when no address is available
            let message = Paragraph::new("No code address available. Run the program first.")
                .style(Style::default().fg(Color::Yellow))
                .wrap(Wrap { trim: true });
            f.render_widget(message, inner_area);
        }
    }
}

/// View for the trace display (function call tracing)
pub struct TraceView;

impl Default for TraceView {
    fn default() -> Self {
        Self::new()
    }
}

impl TraceView {
    pub fn new() -> Self {
        Self
    }
    
    pub fn render<B: Backend>(&self, f: &mut Frame<B>, area: Rect, app: &App) {
        let block = Block::default()
            .title(Line::from(Span::styled(
                "Function Call Trace",
                Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
            )))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(if app.current_view == View::Trace {
                Color::Green
            } else {
                Color::Gray
            }));
        
        let inner_area = block.inner(area);
        f.render_widget(block, area);
        
        // Get the debugger and thread manager
        let debugger = app.get_debugger();
        
        if let Ok(debugger) = debugger.lock() {
            if let Some(thread_manager) = debugger.get_thread_manager() {
                // Get current thread ID
                if let Some(current_thread_id) = thread_manager.current_thread_id() {
                    // Render the call tree for the current thread
                    let call_tree = debugger.get_function_call_tree(current_thread_id);
                    
                    if !call_tree.is_empty() {
                        // Create items for the call tree
                        let items: Vec<ListItem> = call_tree.iter()
                            .map(|call| {
                                // Check if this is an active call (no return time)
                                let style = if call.contains("(active)") {
                                    Style::default().fg(Color::Yellow)
                                } else {
                                    Style::default()
                                };
                                
                                ListItem::new(Line::from(vec![Span::styled(call.clone(), style)]))
                            })
                            .collect();
                        
                        let list = List::new(items)
                            .block(Block::default())
                            .highlight_style(Style::default().add_modifier(Modifier::BOLD));
                        
                        f.render_widget(list, inner_area);
                        return;
                    }
                }
                
                // No call tree for the current thread
                let text = if debugger.is_function_tracing_enabled() {
                    "Function call tracing is enabled, but no calls have been recorded yet."
                } else {
                    "Function call tracing is disabled. Enable it with the 'trace on' command."
                };
                
                let paragraph = Paragraph::new(text)
                    .alignment(Alignment::Center)
                    .style(Style::default().fg(Color::Gray));
                
                f.render_widget(paragraph, inner_area);
            } else {
                // No thread manager
                let text = if debugger.get_state() == crate::debugger::core::DebuggerState::Running {
                    "No thread information available."
                } else {
                    "No program is running."
                };
                
                let paragraph = Paragraph::new(text)
                    .alignment(Alignment::Center)
                    .style(Style::default().fg(Color::Gray));
                
                f.render_widget(paragraph, inner_area);
            }
        } else {
            // Failed to lock debugger
            let paragraph = Paragraph::new("Failed to access debugger.")
                .alignment(Alignment::Center)
                .style(Style::default().fg(Color::Red));
            
            f.render_widget(paragraph, inner_area);
        }
    }
}

/// Draw function call trace view with statistics
pub fn draw_trace_view<B: Backend>(
    f: &mut Frame<B>,
    app: &App,
    area: Rect,
) {
    // Create a layout that splits the area into two sections:
    // 1. Call tree (top, larger)
    // 2. Statistics (bottom)
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage(80), // Call tree takes 80% of space
            Constraint::Percentage(20), // Statistics takes 20% of space
        ])
        .split(area);
    
    // Create the main trace view block
    let trace_view = TraceView::new();
    trace_view.render(f, chunks[0], app);
    
    // Draw statistics in the bottom section
    let block = Block::default()
        .title(Line::from(Span::styled(
            "Call Statistics",
            Style::default().fg(Color::Cyan),
        )))
        .borders(Borders::ALL);
    
    let inner_stats_area = block.inner(chunks[1]);
    f.render_widget(block, chunks[1]);
    
    // Get the debugger to access statistics
    let debugger = app.get_debugger();
    
    if let Ok(debugger) = debugger.lock() {
        // Get trace statistics
        let stats = debugger.get_function_call_stats();
        
        if stats.is_empty() {
            // No statistics available
            let paragraph = Paragraph::new("No function call statistics available.")
                .alignment(Alignment::Center)
                .style(Style::default().fg(Color::Gray));
            
            f.render_widget(paragraph, inner_stats_area);
        } else {
            // Sort by total time spent
            let mut stats_vec: Vec<_> = stats.into_iter().collect();
            stats_vec.sort_by(|a, b| b.1.1.cmp(&a.1.1));
            
            // Create a table of statistics
            let header = Row::new(vec![
                "Function", "Calls", "Total Time", "Avg Time"
            ].into_iter().map(|h| Cell::from(h).style(Style::default().fg(Color::Yellow))))
            .style(Style::default().fg(Color::Yellow));
            
            // Create rows
            let rows = stats_vec.iter().take(inner_stats_area.height as usize).map(|(name, (count, duration))| {
                let avg_time = duration.div_f64(*count as f64);
                Row::new(vec![
                    name.clone(),
                    format!("{}", count),
                    format!("{:.2}ms", duration.as_millis()),
                    format!("{:.2}ms", avg_time.as_millis()),
                ])
            });
            
            let table = Table::new(rows)
                .header(header)
                .block(Block::default())
                .widths(&[
                    Constraint::Percentage(40), // Function name
                    Constraint::Percentage(15), // Call count
                    Constraint::Percentage(25), // Total time
                    Constraint::Percentage(20), // Avg time
                ]);
            
            f.render_widget(table, inner_stats_area);
        }
    } else {
        // Failed to lock debugger
        let paragraph = Paragraph::new("Failed to access debugger.")
            .alignment(Alignment::Center)
            .style(Style::default().fg(Color::Red));
        
        f.render_widget(paragraph, inner_stats_area);
    }
}

/// View for the variables display
pub struct VariablesView;

impl Default for VariablesView {
    fn default() -> Self {
        Self::new()
    }
}

impl VariablesView {
    pub fn new() -> Self {
        Self
    }
    
    pub fn render<B: Backend>(&self, f: &mut Frame<B>, area: Rect, app: &App) {
        let block = Block::default()
            .title(Line::from(Span::styled(
                "Variables",
                Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
            )))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(if app.current_view == View::Variables {
                Color::Green
            } else {
                Color::Gray
            }));
        
        let inner_area = block.inner(area);
        f.render_widget(block, area);
        
        // Try to get the debugger, but handle the case when it's locked
        if let Ok(debugger) = app.get_debugger().try_lock() {
            // Get current frame index
            let frame_index = app.current_frame;
            
            // Create a list of variables to display
            let mut items = Vec::new();
            
            // First, show watch expressions if any
            if app.watch_expressions.is_empty() {
                // No watch expressions - just show variables
                // Get variables for the current frame
                let _frame_vars = debugger.get_variables_by_frame(frame_index);
                
                if _frame_vars.is_empty() {
                    items.push(ListItem::new(Line::from(vec![
                        Span::styled("No variables available in this frame", Style::default().fg(Color::Gray))
                    ])));
                } else {
                    for var in _frame_vars {
                        // Format the variable for display
                        let mut line_style = Style::default();
                        if var.has_changed() {
                            line_style = line_style.fg(Color::Yellow);
                        }
                        
                        items.push(ListItem::new(Line::from(vec![
                            Span::styled(var.format(), line_style)
                        ])));
                    }
                }
            } else {
                items.push(ListItem::new(Line::from(vec![
                    Span::styled("Watched Expressions", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))
                ])));
                
                // Get frame variables before we drop the debugger
                let _frame_vars = debugger.get_variables_by_frame(frame_index);
                
                // Release the immutable borrow to evaluate expressions
                drop(debugger);
                
                // Process each watch expression with its own debugger lock
                for expr in &app.watch_expressions {
                    let expr_result = if let Ok(mut debugger) = app.debugger.try_lock() {
                        match debugger.evaluate_expression(expr) {
                            Ok(value) => format!("{} = {}", expr, value),
                            Err(_) => format!("{} = <error>", expr),
                        }
                    } else {
                        format!("{} = <unavailable>", expr)
                    };
                    
                    items.push(ListItem::new(Line::from(vec![
                        Span::styled(expr_result, Style::default().fg(Color::LightCyan))
                    ])));
                }
                
                // Add a separator
                items.push(ListItem::new(Line::from(vec![
                    Span::styled("─".repeat(inner_area.width as usize), Style::default().fg(Color::DarkGray))
                ])));
                
                // Add a header for regular variables
                items.push(ListItem::new(Line::from(vec![
                    Span::styled("Local Variables", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))
                ])));
                
                // Re-acquire the debugger to show variables
                if let Ok(debugger) = app.debugger.try_lock() {
                    // Get variables again with the new lock
                    let _frame_vars = debugger.get_variables_by_frame(frame_index);
                    
                    if _frame_vars.is_empty() {
                        items.push(ListItem::new(Line::from(vec![
                            Span::styled("No local variables in this frame", Style::default().fg(Color::Gray))
                        ])));
                    } else {
                        for var in _frame_vars {
                            // Format the variable for display
                            let mut line_style = Style::default();
                            if var.has_changed() {
                                line_style = line_style.fg(Color::Yellow);
                            }
                            
                            items.push(ListItem::new(Line::from(vec![
                                Span::styled(var.format(), line_style)
                            ])));
                        }
                    }
                } else {
                    // Couldn't reacquire the debugger
                    items.push(ListItem::new(Line::from(vec![
                        Span::styled("Cannot access debugger to show variables", Style::default().fg(Color::Red))
                    ])));
                }
            }
            
            // If no items to display at all
            if items.is_empty() {
                items.push(ListItem::new(Line::from(vec![
                    Span::styled("No variables or watch expressions available", Style::default().fg(Color::Gray))
                ])));
            }
            
            let list = List::new(items)
                .block(Block::default())
                .highlight_style(Style::default().bg(Color::DarkGray))
                .highlight_symbol("> ");
            
            f.render_widget(list, inner_area);
        }
    }
}

/// Draw code editor view with line numbers and current line highlighted
#[allow(dead_code)]
pub fn draw_code_view<B: Backend>(f: &mut Frame<B>, area: Rect, lines: &[String], selected_line: Option<usize>) {
    let items: Vec<ListItem> = lines
        .iter()
        .enumerate()
        .map(|(i, line)| {
            let style = if selected_line == Some(i) {
                Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };
            
            ListItem::new(Line::from(line.clone())).style(style)
        })
        .collect();

    let list = List::new(items)
        .block(Block::default()
            .borders(Borders::ALL)
            .title("Code")
            .title_alignment(Alignment::Center))
        .highlight_style(Style::default().add_modifier(Modifier::BOLD));
    
    f.render_widget(list, area);
}

// Add a helper function to retrieve watchpoints for a memory range
fn get_watchpoints_for_range(app: &App, start_addr: u64, end_addr: u64) -> Vec<Watchpoint> {
    if let Ok(debugger) = app.get_debugger().try_lock() {
        debugger.get_watchpoints()
            .iter()
            .filter(|wp| {
                let wp_start = wp.address();
                let wp_end = wp.address() + wp.size() as u64;
                
                // Check for overlap with the given range
                wp_start <= end_addr && wp_end >= start_addr
            })
            .cloned()
            .collect()
    } else {
        Vec::new()
    }
}

/// Draw source code view in the specified area
pub fn draw_source_view<B: Backend>(
    f: &mut Frame<B>,
    area: Rect,
    app: &App,
) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title("Source Code");
    
    // Create a list area for source code display
    let inner_area = block.inner(area);
    f.render_widget(block, area);
    
    // Check if DWARF debugging is available
    if !app.is_dwarf_enabled() {
        let message = Line::from(vec![
            Span::styled("DWARF debugging not enabled or debug info not found.", 
                Style::default().fg(Color::Yellow))
        ]);
        
        let paragraph = Paragraph::new(message)
            .alignment(Alignment::Center)
            .wrap(Wrap { trim: true });
        
        f.render_widget(paragraph, inner_area);
        return;
    }
    
    // Check if we have a current source context
    if let Some((file_path, source_lines)) = &app.current_source_context {
        // Create header with file path
        let header = vec![
            Line::from(vec![
                Span::styled("File: ", Style::default().fg(Color::Yellow)),
                Span::raw(file_path),
            ])
        ];
        
        // Create source code lines
        let mut lines = Vec::new();
        
        for (line_num, content, is_current) in source_lines {
            // Format the line number with fixed width
            let line_num_str = format!("{:4} ", line_num);
            
            let mut spans = vec![
                Span::styled(line_num_str, Style::default().fg(Color::Cyan)),
            ];
            
            // If this is the current line, highlight it
            if *is_current {
                spans.push(Span::styled(
                    format!("{}", content), 
                    Style::default()
                        .fg(Color::White)
                        .bg(Color::DarkGray)
                        .add_modifier(Modifier::BOLD)
                ));
            } else {
                spans.push(Span::raw(format!("{}", content)));
            }
            
            lines.push(Line::from(spans));
        }
        
        // Combine header and source lines
        let all_lines: Vec<Line> = header.into_iter().chain(lines).collect();
        
        let source_paragraph = Paragraph::new(all_lines)
            .scroll((app.source_scroll as u16, 0))
            .wrap(Wrap { trim: false });
        
        f.render_widget(source_paragraph, inner_area);
    } else {
        let message = Line::from(vec![
            Span::styled("No source code available for the current location.", 
                Style::default().fg(Color::Yellow))
        ]);
        
        let paragraph = Paragraph::new(message)
            .alignment(Alignment::Center)
            .wrap(Wrap { trim: true });
        
        f.render_widget(paragraph, inner_area);
    }
}
