//! RUSTCAT - MacOS-only, Rust-based, fast-as-hell native debugger
//!
//! This library provides the core functionality of the RUSTCAT debugger,
//! which can be used both as a standalone application and as a library
//! for testing and integrating with other tools.

pub mod tui;
pub mod debugger;
pub mod platform;

/// Re-export key modules for easier access in tests
pub use debugger::core::Debugger;
pub use debugger::memory::{MemoryMap, MemoryRegion, Protection, MemoryFormat};
pub use tui::app::{App, View, Command as AppCommand};

/// Version information
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const PKG_NAME: &str = env!("CARGO_PKG_NAME");
pub const PKG_DESCRIPTION: &str = env!("CARGO_PKG_DESCRIPTION");

/// Initialize the logging system
pub fn init_logging(level: log::LevelFilter) {
    env_logger::Builder::new()
        .filter_level(level)
        .filter_module("rustcat", level)
        .format_timestamp_secs()
        .init();
}

/// Parse a command string (wrapper around App::parse_command)
pub fn parse_command(cmd_str: &str) -> Result<AppCommand, String> {
    // This is a temporary wrapper to make the tests compile
    // In a real implementation, we'd either move command parsing to a separate module
    // or correctly expose it from App
    Err("Command parsing not yet implemented for tests".to_string())
} 