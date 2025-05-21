use ratatui::{
    widgets::{Block, Borders, Paragraph, Wrap},
    layout::Rect,
    style::{Style, Color},
    text::{Span, Line as Spans},
    Frame
};

use crate::debugger::core::Debugger;

pub struct MemoryView {
    pub address: usize,
    pub scroll_offset: usize,
    pub bytes_per_row: usize,
    pub rows: usize,
    pub show_ascii: bool,
}

impl MemoryView {
    pub fn new() -> Self {
        Self {
            address: 0,
            scroll_offset: 0,
            bytes_per_row: 16,
            rows: 16,
            show_ascii: true,
        }
    }

    pub fn render(&self, f: &mut Frame, area: Rect, _debugger: &Debugger) {
        // Create a block with borders
        let block = Block::default()
            .title("Memory")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan));
        
        // Placeholder memory dump
        let mut text = Vec::new();
        
        // Generate a fake memory dump for UI mockup
        for i in 0..self.rows {
            let addr = self.address + (i * self.bytes_per_row);
            let mut line = format!("{:08x}:  ", addr);
            
            // Fake hex bytes
            for j in 0..self.bytes_per_row {
                let byte_val = ((addr + j) % 256) as u8;
                line.push_str(&format!("{:02x} ", byte_val));
                
                // Add extra space in the middle for readability
                if j == 7 {
                    line.push(' ');
                }
            }
            
            // ASCII representation if enabled
            if self.show_ascii {
                line.push_str("  |");
                for j in 0..self.bytes_per_row {
                    let byte_val = ((addr + j) % 256) as u8;
                    // Only print ASCII for printable characters
                    let ch = if byte_val >= 32 && byte_val <= 126 {
                        byte_val as char
                    } else {
                        '.'
                    };
                    line.push(ch);
                }
                line.push('|');
            }
            
            text.push(Spans::from(vec![
                Span::styled(line, Style::default())
            ]));
        }
        
        // Create the widget from the text
        let paragraph = Paragraph::new(text)
            .block(block)
            .wrap(Wrap { trim: true });
        
        // Render the widget
        f.render_widget(paragraph, area);
    }
} 