#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

// Make it easier to import the module
use rustcat::debugger::symbols::{SymbolTable, Symbol, SymbolType};

#[derive(Arbitrary, Debug)]
struct DwarfFuzzInput {
    // The raw binary data to fuzz with
    data: Vec<u8>,
    // Flags to test different behaviors
    try_as_elf: bool,
    try_as_macho: bool,
    try_as_pe: bool,
}

fuzz_target!(|input: DwarfFuzzInput| {
    // Prepare a temporary file
    let temp_dir = std::env::temp_dir();
    let file_path = temp_dir.join(format!("dwarf_fuzz_{}.bin", std::process::id()));
    
    // Write the fuzzed data to the file
    if let Ok(mut file) = File::create(&file_path) {
        // Only proceed if we can create the file
        if let Ok(_) = file.write_all(&input.data) {
            // Try to parse as a symbol table
            let mut symbol_table = SymbolTable::new();
            
            // Don't let errors crash the fuzzer
            let _ = symbol_table.load_from_file(&file_path);
            
            // Try a few operations on the symbol table to ensure they're safe
            if !symbol_table.is_empty() {
                // Try to find a symbol at various addresses
                for addr in [0, 1, 100, 0x1000, 0x10000, 0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF] {
                    let _ = symbol_table.find_by_address(addr);
                    let _ = symbol_table.find_by_address_range(addr);
                }
                
                // Try to find symbols by name
                let _ = symbol_table.find_by_name("main");
                let _ = symbol_table.find_by_prefix("ma");
                
                // Try different symbol types
                for symbol_type in [SymbolType::Function, SymbolType::GlobalVariable, SymbolType::StaticVariable] {
                    let _ = symbol_table.find_by_type(symbol_type);
                }
            }
        }
    }
    
    // Clean up the temporary file
    let _ = std::fs::remove_file(file_path);
}); 