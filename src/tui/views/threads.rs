use ratatui::{
    widgets::{Block, Borders, Paragraph, Wrap},
    layout::Rect,
    style::{Style, Color},
    text::{Span, Line as Spans},
    Frame
};

use crate::debugger::core::Debugger;

pub struct ThreadsView {
    pub selected_thread: usize,
    pub scroll_offset: usize,
    pub visible_threads: usize,
}

impl ThreadsView {
    pub fn new() -> Self {
        Self {
            selected_thread: 0,
            scroll_offset: 0,
            visible_threads: 20,
        }
    }

    pub fn render(&self, f: &mut Frame, area: Rect, _debugger: &Debugger) {
        // Create a block with borders
        let block = Block::default()
            .title("Threads")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan));
        
        // Placeholder threads list
        let mut text = Vec::new();
        
        // Generate dummy thread list for UI mockup
        let threads = [
            "Thread 1 (Main Thread): Running",
            "Thread 2 (Worker): Waiting",
            "Thread 3 (UI): Running",
            "Thread 4 (Network): Blocked"
        ];
        
        if !threads.is_empty() {
            for (i, thread) in threads.iter().enumerate() {
                let style = if i == self.selected_thread {
                    Style::default().fg(Color::Yellow)
                } else {
                    Style::default()
                };
                
                text.push(Spans::from(vec![
                    Span::styled(*thread, style)
                ]));
            }
        } else {
            text.push(Spans::from(vec![
                Span::styled("No threads", Style::default().fg(Color::Gray))
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