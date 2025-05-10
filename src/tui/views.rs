use ratatui::{
    backend::Backend,
    layout::{Rect, Alignment},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph},
    Frame,
};

use crate::tui::app::{App, View};
use crate::debugger::memory::MemoryFormat;

/// View for the code display
pub struct CodeView;

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

impl MemoryView {
    pub fn new() -> Self {
        Self
    }

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

impl RegistersView {
    pub fn new() -> Self {
        Self
    }

    pub fn render<B: Backend>(&self, f: &mut Frame<B>, area: Rect) {
        let registers = vec![
            "rax: 0x0000000100000f24",
            "rbx: 0x0000000000000000",
            "rcx: 0x00007ff7bfeff680",
            "rdx: 0x00007ff7bfeff698",
            "rsi: 0x00007ff7bfeff688",
            "rdi: 0x0000000000000001",
            "rbp: 0x00007ff7bfeff6a0",
            "rsp: 0x00007ff7bfeff648",
            "r8:  0x0000000000000000",
            "r9:  0x0000000000000000",
        ];
        
        let items: Vec<ListItem> = registers
            .iter()
            .map(|r| ListItem::new(vec![Line::from(*r)]))
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

impl StackView {
    pub fn new() -> Self {
        Self
    }

    pub fn render<B: Backend>(&self, f: &mut Frame<B>, area: Rect) {
        let stack_frames = vec![
            "#0 0x0000000100000f24 main()",
            "#1 0x00007ff7bfc01014 start + 0",
        ];
        
        let items: Vec<ListItem> = stack_frames
            .iter()
            .map(|s| ListItem::new(vec![Line::from(*s)]))
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

impl ThreadsView {
    pub fn new() -> Self {
        Self
    }

    pub fn render<B: Backend>(&self, f: &mut Frame<B>, area: Rect) {
        let threads = vec![
            "Thread 0x1103 (main)",
            "Thread 0x1503 (worker)",
            "Thread 0x1703 (worker)",
        ];
        
        let items: Vec<ListItem> = threads
            .iter()
            .map(|t| ListItem::new(vec![Line::from(*t)]))
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

impl CommandView {
    pub fn new() -> Self {
        Self
    }

    pub fn render<B: Backend>(&self, f: &mut Frame<B>, area: Rect) {
        let text = vec![
            Line::from(vec![
                Span::raw("> "),
                Span::styled("break main", Style::default().fg(Color::Yellow)),
            ]),
        ];
        
        let paragraph = Paragraph::new(text)
            .block(Block::default().borders(Borders::ALL).title("Command"))
            .style(Style::default().fg(Color::White));
        
        f.render_widget(paragraph, area);
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
    let block = Block::default()
        .title(Span::styled(
            format!("Memory - {}", app.get_memory_format().name()),
            Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
        ))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(if app.current_view == View::Memory {
            Color::Green
        } else {
            Color::Gray
        }));
    
    let inner_area = block.inner(area);
    f.render_widget(block, area);
    
    if let Some(data) = memory_data {
        // Calculate how many bytes fit per row (16 bytes is standard)
        let bytes_per_row = 16;
        
        // Calculate visible rows
        let visible_rows = inner_area.height as usize;
        
        // Check if we should use specialized formatting
        if app.get_memory_format() != MemoryFormat::Hex && 
           app.get_memory_format() != MemoryFormat::Ascii {
            // Use specialized formatters
            // Create a debugger instance to format the memory
            if let Ok(debugger) = crate::debugger::core::Debugger::new("dummy") {
                let formatted = debugger.format_memory(data, app.get_memory_format());
                let lines: Vec<&str> = formatted.lines().take(visible_rows).collect();
                
                let text: Vec<Line> = lines.into_iter()
                    .map(|line| Line::from(line))
                    .collect();
                
                let memory_paragraph = Paragraph::new(text)
                    .style(Style::default().fg(Color::White))
                    .block(Block::default());
                
                f.render_widget(memory_paragraph, inner_area);
                return;
            }
        }
        
        // Calculate total rows
        let total_rows = (data.len() + bytes_per_row - 1) / bytes_per_row;
        
        // Prepare rows of text
        let mut rows = Vec::with_capacity(visible_rows.min(total_rows));
        
        for row_idx in 0..visible_rows.min(total_rows) {
            let row_address = memory_address + (row_idx * bytes_per_row) as u64;
            let start_idx = row_idx * bytes_per_row;
            let end_idx = (start_idx + bytes_per_row).min(data.len());
            
            // Generate address column
            let address_text = format!("{:016x}", row_address);
            let address_span = Span::styled(
                address_text,
                Style::default().fg(Color::Yellow),
            );
            
            // Generate hex representation
            let mut hex_text = String::with_capacity(bytes_per_row * 3);
            let mut ascii_text = String::with_capacity(bytes_per_row);
            
            for i in start_idx..end_idx {
                let byte = data[i];
                
                // Add hex representation
                hex_text.push_str(&format!("{:02x} ", byte));
                
                // Add ASCII representation (only printable characters)
                if byte >= 32 && byte <= 126 {
                    ascii_text.push(byte as char);
                } else {
                    ascii_text.push('.');
                }
            }
            
            // Pad hex text if needed
            if end_idx - start_idx < bytes_per_row {
                for _ in 0..(bytes_per_row - (end_idx - start_idx)) {
                    hex_text.push_str("   ");
                    ascii_text.push(' ');
                }
            }
            
            // Create spans for the row
            let hex_span = Span::styled(
                hex_text,
                Style::default().fg(Color::White),
            );
            
            let ascii_span = Span::styled(
                ascii_text,
                Style::default().fg(Color::Cyan),
            );
            
            // Combine spans into a row
            let row = Line::from(vec![
                address_span,
                Span::raw(" | "),
                hex_span,
                Span::raw(" | "),
                ascii_span,
            ]);
            
            rows.push(row);
        }
        
        // Create paragraph with all rows
        let memory_paragraph = Paragraph::new(rows)
            .style(Style::default().fg(Color::White))
            .block(Block::default());
        
        f.render_widget(memory_paragraph, inner_area);
    } else {
        // No memory data available
        let text = vec![
            Line::from(vec![
                Span::styled(
                    "No memory data available.",
                    Style::default().fg(Color::Red),
                ),
            ]),
            Line::from(vec![
                Span::styled(
                    "Use 'memory <address> <size>' to view memory.",
                    Style::default().fg(Color::Yellow),
                ),
            ]),
        ];
        
        let help_para = Paragraph::new(text)
            .style(Style::default())
            .block(Block::default())
            .alignment(Alignment::Center);
        
        f.render_widget(help_para, inner_area);
    }
}
