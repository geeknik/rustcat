#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::Arbitrary;
use rustcat::debugger::memory::{MemoryMap, MemoryRegion, Protection, MemoryFormat};

#[derive(Arbitrary, Debug)]
struct MemoryFuzzInput {
    // Region parameters
    base: u64,
    size: u64,
    protection_idx: u8,  // Will be mapped to Protection enum
    
    // Test addresses
    test_addresses: Vec<u64>,
    
    // Memory formatting
    format_idx: u8,  // Will be mapped to MemoryFormat enum
    data: Vec<u8>,   // Data to format
}

// Map u8 to Protection
fn to_protection(idx: u8) -> Protection {
    match idx % 8 {
        0 => Protection::Read,
        1 => Protection::Write,
        2 => Protection::Execute,
        3 => Protection::ReadWrite,
        4 => Protection::ReadExecute,
        5 => Protection::WriteExecute,
        6 => Protection::ReadWriteExecute,
        _ => Protection::None,
    }
}

// Map u8 to MemoryFormat
fn to_memory_format(idx: u8) -> MemoryFormat {
    match idx % 14 {
        0 => MemoryFormat::Hex,
        1 => MemoryFormat::Ascii,
        2 => MemoryFormat::Utf8,
        3 => MemoryFormat::Disassembly,
        4 => MemoryFormat::U8,
        5 => MemoryFormat::U16,
        6 => MemoryFormat::U32,
        7 => MemoryFormat::U64,
        8 => MemoryFormat::I8,
        9 => MemoryFormat::I16,
        10 => MemoryFormat::I32,
        11 => MemoryFormat::I64,
        12 => MemoryFormat::F32,
        _ => MemoryFormat::F64,
    }
}

fuzz_target!(|input: MemoryFuzzInput| {
    // Create a memory map for fuzzing
    let mut map = MemoryMap::new();
    
    // Create a region with fuzzed parameters
    let protection = to_protection(input.protection_idx);
    let region_name = format!("fuzz_region_{}", input.base);
    
    // Ensure we don't have zero-size regions
    let size = if input.size == 0 { 1 } else { input.size };
    
    let region = MemoryRegion::new(
        input.base,
        size,
        protection,
        Some(region_name.clone()),
        false,
        true,
    );
    
    // Add the region to the map
    map.add_region(region);
    
    // Test address lookups
    for addr in input.test_addresses {
        let _ = map.find_region(addr);
        let _ = map.describe_address(addr);
    }
    
    // Test memory tracking
    if !input.test_addresses.is_empty() {
        let first_addr = input.test_addresses[0];
        map.track_allocation("fuzz_allocation", first_addr, 128);
        let _ = map.describe_address(first_addr);
        map.untrack_allocation("fuzz_allocation");
    }
    
    // Test memory formatting
    if !input.data.is_empty() {
        let format = to_memory_format(input.format_idx);
        let _ = map.format_memory(&input.data, format);
    }
}); 