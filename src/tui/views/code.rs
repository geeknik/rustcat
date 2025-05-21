use ratatui::{
    widgets::{Block, Borders, Paragraph, Wrap},
    layout::Rect,
    style::{Style, Color},
    text::{Span, Line as Spans, Text},
    Frame, backend::Backend
};

use crate::debugger::core::Debugger;

pub struct CodeView {
    // Current location in code (address)
    pub current_address: usize,
    // Line position for scrolling
    pub scroll_offset: usize,
    // Visible instruction count
    pub visible_lines: usize,
    // Whether we're viewing source code or disassembly
    pub show_source: bool,
    // Highlights for current line
    pub highlight_current: bool,
}

impl CodeView {
    pub fn new() -> Self {
        Self {
            current_address: 0,
            scroll_offset: 0,
            visible_lines: 20,
            show_source: true,
            highlight_current: true,
        }
    }

    pub fn render(&self, f: &mut Frame, area: Rect, _debugger: &Debugger) {
        // Create a block with borders
        let block = Block::default()
            .title("Code")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan));
        
        // Generate dummy disassembly for now
        let mut text = Vec::new();
        
        // Check if we have a program loaded
        // Note: Temporary placeholder - need to implement Debugger::is_loaded
        let program_loaded = true; // Assume loaded for now
        
        if program_loaded {
            // Disassembly view (for now just placeholder)
            for i in 0..self.visible_lines {
                let line_address = self.current_address + i * 4;
                let instruction = format!("{:08x}: instruction", line_address);
                
                // Highlight current line
                let style = if i == 0 && self.highlight_current {
                    Style::default().fg(Color::Yellow)
                } else {
                    Style::default()
                };
                
                text.push(Spans::from(vec![
                    Span::styled(instruction, style)
                ]));
            }
        } else {
            // No program loaded
            text.push(Spans::from(vec![
                Span::styled("No program loaded", Style::default().fg(Color::Gray))
            ]));
            text.push(Spans::from(vec![
                Span::styled("Use 'load <filename>' to load a program", Style::default().fg(Color::Gray))
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