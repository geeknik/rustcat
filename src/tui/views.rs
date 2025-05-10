use ratatui::{
    backend::Backend,
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph},
    Frame,
};

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
