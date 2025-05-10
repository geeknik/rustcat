#[cfg(target_os = "macos")]
pub mod macos;
pub mod dwarf;

#[cfg(not(target_os = "macos"))]
pub mod dummy {
    // This module provides stub implementations for non-macOS platforms
    // so the project can compile for CI and documentation purposes
    
    use anyhow::{anyhow, Result};
    use crate::debugger::registers::Registers;

    pub struct MacosDebugger;

    impl MacosDebugger {
        pub fn new() -> Self {
            Self {}
        }

        pub fn launch(&mut self, _program: &str) -> Result<i32> {
            Err(anyhow!("MacosDebugger is only available on macOS"))
        }

        pub fn attach(&mut self, _pid: i32) -> Result<()> {
            Err(anyhow!("MacosDebugger is only available on macOS"))
        }

        pub fn detach(&mut self, _pid: i32) -> Result<()> {
            Err(anyhow!("MacosDebugger is only available on macOS"))
        }

        pub fn continue_execution(&mut self, _pid: i32) -> Result<()> {
            Err(anyhow!("MacosDebugger is only available on macOS"))
        }

        pub fn set_breakpoint(&mut self, _pid: i32, _address: u64) -> Result<u8> {
            Err(anyhow!("MacosDebugger is only available on macOS"))
        }

        pub fn remove_breakpoint(&mut self, _pid: i32, _address: u64, _original_byte: u8) -> Result<()> {
            Err(anyhow!("MacosDebugger is only available on macOS"))
        }

        pub fn get_registers(&self, _pid: i32) -> Result<Registers> {
            Err(anyhow!("MacosDebugger is only available on macOS"))
        }

        pub fn set_registers(&self, _pid: i32, _registers: &Registers) -> Result<()> {
            Err(anyhow!("MacosDebugger is only available on macOS"))
        }

        pub fn read_memory(&self, _pid: i32, _address: u64, _size: usize) -> Result<Vec<u8>> {
            Err(anyhow!("MacosDebugger is only available on macOS"))
        }

        pub fn write_memory(&self, _pid: i32, _address: u64, _data: &[u8]) -> Result<()> {
            Err(anyhow!("MacosDebugger is only available on macOS"))
        }

        pub fn step(&mut self, _pid: i32) -> Result<()> {
            Err(anyhow!("MacosDebugger is only available on macOS"))
        }

        pub fn kill(&mut self, _pid: i32) -> Result<()> {
            Err(anyhow!("MacosDebugger is only available on macOS"))
        }

        pub fn wait_for_stop(&self, _pid: i32, _timeout_ms: u64) -> Result<()> {
            Err(anyhow!("MacosDebugger is only available on macOS"))
        }
    }

    impl Default for MacosDebugger {
        fn default() -> Self {
            Self::new()
        }
    }
}

// Re-export the appropriate implementation based on platform
#[cfg(target_os = "macos")]
pub use macos::MacosDebugger;

#[cfg(not(target_os = "macos"))]
pub use dummy::MacosDebugger;
