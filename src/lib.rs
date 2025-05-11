#![allow(clippy::multiple_crate_versions)]
#![allow(clippy::struct_excessive_bools)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::uninlined_format_args)]
#![allow(clippy::significant_drop_tightening)]
#![allow(clippy::cognitive_complexity)]
#![allow(clippy::too_many_lines)]
#![allow(clippy::unnecessary_wraps)]
#![allow(clippy::option_if_let_else)]
#![allow(clippy::match_on_vec_items)]
#![allow(clippy::manual_let_else)]
#![allow(clippy::match_same_arms)]
#![allow(clippy::used_underscore_binding)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::needless_pass_by_value)]
#![allow(clippy::items_after_statements)]
#![allow(clippy::branches_sharing_code)]
#![allow(clippy::equatable_if_let)]
#![allow(clippy::must_use_candidate)]
#![allow(clippy::missing_const_for_fn)]

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
    // Use a real App instance to parse the command
    // This assumes App::parse_command is a pure function (does not require full App state)
    // If not, refactor App::parse_command to be a standalone function or move to a command module
    let app = App::new(Debugger::new("/dev/null").map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
    Ok(app.parse_command(cmd_str))
} 