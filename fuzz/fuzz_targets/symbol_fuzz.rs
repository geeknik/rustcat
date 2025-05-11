#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use rustcat::debugger::symbols::{Symbol, SymbolType};

#[derive(Arbitrary, Debug)]
struct SymbolFuzzInput {
    // Test various symbol names including potentially malformed ones
    names: Vec<String>,
    // Test different symbol types
    type_idx: u8,
    // Test different addresses
    address: u64,
    // Test optional fields
    has_size: bool,
    size: u64,
    has_visibility: bool,
    has_source_file: bool,
    has_line_number: bool,
    line_number: u32,
}

// Map u8 to SymbolType
fn to_symbol_type(idx: u8) -> SymbolType {
    match idx % 7 {
        0 => SymbolType::Function,
        1 => SymbolType::GlobalVariable,
        2 => SymbolType::StaticVariable,
        3 => SymbolType::Text,
        4 => SymbolType::Data,
        5 => SymbolType::Debug,
        _ => SymbolType::Other,
    }
}

fuzz_target!(|input: SymbolFuzzInput| {
    // Skip if there are no names to test
    if input.names.is_empty() {
        return;
    }
    
    for name in &input.names {
        // Skip empty names
        if name.is_empty() {
            continue;
        }
        
        // Create a symbol with the fuzzed parameters
        let symbol_type = to_symbol_type(input.type_idx);
        let size = if input.has_size { Some(input.size) } else { None };
        let visibility = if input.has_visibility { 
            Some(match input.address % 3 {
                0 => "global".to_string(),
                1 => "local".to_string(),
                _ => "private".to_string(),
            }) 
        } else { 
            None 
        };
        
        let source_file = if input.has_source_file {
            Some(format!("file_{}.c", input.address % 100))
        } else {
            None
        };
        
        let line = if input.has_line_number {
            Some(input.line_number)
        } else {
            None
        };
        
        // Create the symbol - don't let failures crash the fuzzer
        let symbol = Symbol::new(
            name.clone(),
            input.address,
            size,
            symbol_type,
            source_file,
            line,
            visibility,
        );
        
        // Try various operations on the symbol
        let _ = symbol.address();
        let _ = symbol.name();
        let _ = symbol.demangled_name();
        let _ = symbol.symbol_type();
        let _ = symbol.size();
        let _ = symbol.line();
        let _ = symbol.source_file();
        
        // Test display formatting (should never panic)
        let _ = format!("{}", symbol);
        let _ = format!("{:?}", symbol);
    }
}); 