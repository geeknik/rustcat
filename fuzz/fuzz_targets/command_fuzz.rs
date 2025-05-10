#![no_main]

use libfuzzer_sys::fuzz_target;
use rustcat::parse_command;

fuzz_target!(|data: &[u8]| {
    // Convert bytes to a string (if valid UTF-8)
    if let Ok(s) = std::str::from_utf8(data) {
        // Try to parse the command
        let _ = parse_command(s);
    }
}); 