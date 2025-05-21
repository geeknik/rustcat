pub mod code;
pub mod stack;
pub mod memory;
pub mod threads;

// Re-export view components
pub use code::CodeView;
pub use stack::StackView;
pub use memory::MemoryView;
pub use threads::ThreadsView; 