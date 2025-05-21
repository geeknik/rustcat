use ratatui::{
    widgets::{Block, Borders, Paragraph, Wrap},
    layout::Rect,
    style::{Style, Color},
    text::{Span, Line as Spans},
    Frame
};

use crate::debugger::core::Debugger;

pub struct StackView {
    pub selected_frame: usize,
    pub scroll_offset: usize,
    pub visible_lines: usize,
}

impl StackView {
    pub fn new() -> Self {
        Self {
            selected_frame: 0,
            scroll_offset: 0,
            visible_lines: 20,
        }
    }

    pub fn render(&self, f: &mut Frame, area: Rect, _debugger: &Debugger) {
        // Create a block with borders
        let block = Block::default()
            .title("Stack")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan));
        
        // Placeholder stack frames
        let mut text = Vec::new();
        
        // Check if there are stack frames (placeholder)
        if true {
            // Fake stack frames for visualization
            let frames = [
                "#0 main() at main.c:10",
                "#1 __start() at crt0.S:15",
                "#2 _start() at crt1.c:30",
            ];
            
            for (i, frame) in frames.iter().enumerate() {
                let style = if i == self.selected_frame {
                    Style::default().fg(Color::Yellow)
                } else {
                    Style::default()
                };
                
                text.push(Spans::from(vec![
                    Span::styled(*frame, style)
                ]));
            }
        } else {
            text.push(Spans::from(vec![
                Span::styled("No stack frames available", Style::default().fg(Color::Gray))
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