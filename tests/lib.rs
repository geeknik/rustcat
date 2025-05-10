//! RUSTCAT Test Suite
//!
//! This file serves as the entry point for all tests in the RUSTCAT project.
//! It integrates various test modules focused on testing security-sensitive
//! components of the debugger.

// Memory tests
#[cfg(test)]
mod memory;

// Input validation tests
#[cfg(test)]
mod input;

// Process control tests
#[cfg(test)]
mod process;

// Platform-specific tests
#[cfg(test)]
mod platform;

// Integration tests
#[cfg(test)]
mod integration;

/// Helper functions for tests that need mock data
#[cfg(test)]
pub mod test_helpers {
    use std::path::PathBuf;
    
    /// Get the path to test binaries directory
    pub fn test_binaries_dir() -> PathBuf {
        let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("tests");
        path.push("binaries");
        path
    }
    
    /// Get the path to a specific test binary
    pub fn test_binary_path(name: &str) -> PathBuf {
        let mut path = test_binaries_dir();
        path.push(name);
        path
    }
} 