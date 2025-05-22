use ratatui::{
    widgets::{Paragraph, Block, Borders, Wrap, Clear},
    layout::Rect,
    style::{Style, Color},
    text::{Span, Line as Spans},
    Frame
};
use crossterm::event::{KeyCode, KeyEvent};
use std::time::{Duration, Instant};

use crate::debugger::core::Debugger;
use crate::tui::app::Command;

/// Command input mode for the TUI
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputMode {
    Normal,
    Editing,
}

pub struct CommandView {
    pub input: String,
    pub cursor_position: usize,
    pub input_mode: InputMode,
    pub command_history: Vec<String>,
    pub history_index: usize,
    pub last_command: Option<Command>,
    pub show_command_bar: bool,
    pub message: Option<(String, Instant, Duration)>,
}

impl CommandView {
    pub fn new() -> Self {
        Self {
            input: String::new(),
            cursor_position: 0,
            input_mode: InputMode::Normal,
            command_history: Vec::new(),
            history_index: 0,
            last_command: None,
            show_command_bar: false,
            message: None,
        }
    }

    /// Render the command view
    pub fn render(&self, f: &mut Frame, area: Rect, _debugger: &Debugger) {
        // Only render when in editing mode or if we have a message to display
        if self.input_mode == InputMode::Normal && self.message.is_none() && !self.show_command_bar {
            return;
        }

        // Create a block for the command input
        let block = Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray));

        // Command input text
        let input_text = match self.input_mode {
            InputMode::Normal => {
                if let Some((msg, _, _)) = &self.message {
                    vec![Spans::from(vec![
                        Span::styled(msg, Style::default().fg(Color::LightBlue))
                    ])]
                } else if self.show_command_bar {
                    vec![Spans::from(vec![
                        Span::styled("Press ':' to enter command mode", Style::default().fg(Color::DarkGray))
                    ])]
                } else {
                    vec![]
                }
            },
            InputMode::Editing => {
                vec![Spans::from(vec![
                    Span::styled(format!(":{}", self.input), Style::default())
                ])]
            }
        };

        // Create a paragraph widget for the input
        let input_paragraph = Paragraph::new(input_text)
            .block(block)
            .wrap(Wrap { trim: true });

        // Render the widget
        f.render_widget(Clear, area); // Clear the area first
        f.render_widget(input_paragraph, area);

        // Show cursor when in editing mode
        if self.input_mode == InputMode::Editing {
            // Move cursor to the right position
            // The +1 accounts for the colon at the start
            f.set_cursor(area.x + self.cursor_position as u16 + 1, area.y + 1);
        }
    }

    pub fn handle_key(&mut self, key: KeyEvent) -> Option<Command> {
        match self.input_mode {
            InputMode::Normal => match key.code {
                KeyCode::Char(':') => {
                    self.input_mode = InputMode::Editing;
                    self.show_command_bar = true;
                    None
                },
                _ => None,
            },
            InputMode::Editing => match key.code {
                KeyCode::Enter => {
                    // Process command
                    let command = self.process_command();
                    
                    // Add to history if not empty
                    if !self.input.is_empty() {
                        self.command_history.push(self.input.clone());
                        self.history_index = self.command_history.len();
                    }
                    
                    // Clear input and return to normal mode
                    self.input.clear();
                    self.cursor_position = 0;
                    self.input_mode = InputMode::Normal;
                    
                    command
                },
                KeyCode::Char(c) => {
                    self.input.insert(self.cursor_position, c);
                    self.cursor_position += 1;
                    None
                },
                KeyCode::Backspace => {
                    if self.cursor_position > 0 {
                        self.cursor_position -= 1;
                        self.input.remove(self.cursor_position);
                    } else if self.input.is_empty() {
                        // Exit command mode if backspace on empty input
                        self.input_mode = InputMode::Normal;
                    }
                    None
                },
                KeyCode::Delete => {
                    if self.cursor_position < self.input.len() {
                        self.input.remove(self.cursor_position);
                    }
                    None
                },
                KeyCode::Left => {
                    if self.cursor_position > 0 {
                        self.cursor_position -= 1;
                    }
                    None
                },
                KeyCode::Right => {
                    if self.cursor_position < self.input.len() {
                        self.cursor_position += 1;
                    }
                    None
                },
                KeyCode::Home => {
                    self.cursor_position = 0;
                    None
                },
                KeyCode::End => {
                    self.cursor_position = self.input.len();
                    None
                },
                KeyCode::Up => {
                    // Go back in history
                    if !self.command_history.is_empty() && self.history_index > 0 {
                        self.history_index -= 1;
                        self.input = self.command_history[self.history_index].clone();
                        self.cursor_position = self.input.len();
                    }
                    None
                },
                KeyCode::Down => {
                    // Go forward in history
                    if self.history_index < self.command_history.len() - 1 {
                        self.history_index += 1;
                        self.input = self.command_history[self.history_index].clone();
                        self.cursor_position = self.input.len();
                    } else if self.history_index == self.command_history.len() - 1 {
                        // At the end of history, show empty input
                        self.history_index = self.command_history.len();
                        self.input.clear();
                        self.cursor_position = 0;
                    }
                    None
                },
                KeyCode::Esc => {
                    // Exit command mode
                    self.input_mode = InputMode::Normal;
                    self.input.clear();
                    self.cursor_position = 0;
                    None
                },
                KeyCode::Tab => {
                    // Implement command completion here
                    None
                },
                _ => None,
            },
        }
    }

    pub fn show_message(&mut self, msg: String, duration: Duration) {
        self.message = Some((msg, Instant::now(), duration));
    }

    pub fn update(&mut self) {
        // Check if message should be cleared
        if let Some((_, created, duration)) = &self.message {
            if created.elapsed() >= *duration {
                self.message = None;
            }
        }
    }

    fn process_command(&mut self) -> Option<Command> {
        // Simple command parsing for now
        let input = self.input.trim();
        
        // Parse command (this will be moved to the Command parser)
        let parts: Vec<&str> = input.split_whitespace().collect();
        if parts.is_empty() {
            return None;
        }
        
        // Return a command based on the input
        let command = match parts[0] {
            "run" | "r" => Some(Command::Run),
            "continue" | "c" => Some(Command::Continue),
            "step" | "s" => Some(Command::Step),
            "next" | "n" => Some(Command::StepOver),
            "finish" | "f" => Some(Command::StepOut),
            "break" | "b" => {
                if parts.len() >= 2 {
                    Some(Command::SetBreakpoint(parts[1].to_string()))
                } else {
                    self.show_message("Missing breakpoint location".to_string(), Duration::from_secs(3));
                    None
                }
            },
            "clear" => {
                if parts.len() >= 2 {
                    if let Ok(idx) = parts[1].parse::<usize>() {
                        Some(Command::ClearBreakpoint(idx))
                    } else {
                        self.show_message(format!("Invalid breakpoint index: {}", parts[1]), Duration::from_secs(3));
                        None
                    }
                } else {
                    self.show_message("Missing breakpoint index".to_string(), Duration::from_secs(3));
                    None
                }
            },
            "quit" | "q" => Some(Command::Quit),
            "help" | "h" => Some(Command::ShowHelp),
            _ => {
                self.show_message(format!("Unknown command: {}", parts[0]), Duration::from_secs(3));
                None
            }
        };
        
        // Store the command for history
        self.last_command = command.clone();
        
        command
    }
} 