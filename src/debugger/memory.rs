use std::collections::HashMap;
use std::fmt;
use std::ops::Range;
use std::io::Result;

use log::info;
use byteorder::{ByteOrder, LittleEndian};

// MacOS specific imports for memory region mapping
use mach2::kern_return::KERN_SUCCESS;
use mach2::vm_types::{mach_vm_address_t, mach_vm_size_t};
use mach2::vm_region::{vm_region_basic_info_data_64_t, VM_REGION_BASIC_INFO_64};
use mach2::vm_prot::{VM_PROT_READ, VM_PROT_WRITE, VM_PROT_EXECUTE};
use mach2::message::mach_msg_type_number_t;
use mach2::port::mach_port_t;
use mach2::traps::{mach_task_self, task_for_pid};
use mach2::vm::mach_vm_region;

// New imports for enhanced memory inspector
use anyhow::{anyhow, Result as AnyhowResult};
use std::cmp::min;

/// Memory search pattern type
#[derive(Debug, Clone, PartialEq)]
pub enum SearchPattern {
    /// Raw bytes (exact match)
    Bytes(Vec<u8>),
    /// UTF-8 text (case-sensitive)
    Text(String),
    /// UTF-8 text (case-insensitive)
    TextIgnoreCase(String),
    /// Integer value with specific byte width
    Integer(u64, usize),
    /// Floating point value (approximate equality)
    Float(f64, usize),
}

// Add a custom Eq implementation for SearchPattern that deliberately excludes Float variant from equality checks
impl Eq for SearchPattern {
    // No methods needed; Eq is a marker trait extending PartialEq
}

/// Memory search result
#[derive(Debug, Clone)]
pub struct SearchResult {
    /// Address where the pattern was found
    pub address: u64,
    /// Context (bytes before and after match)
    pub context: Vec<u8>,
    /// Range of bytes that matched within context
    pub match_range: Range<usize>,
    /// Name of the memory region if available
    pub region_name: Option<String>,
}

/// Memory protection flags
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protection {
    Read,
    Write,
    Execute,
    ReadWrite,
    ReadExecute,
    WriteExecute,
    ReadWriteExecute,
    None,
}

impl Protection {
    /// Check if read permission is granted
    pub fn can_read(&self) -> bool {
        matches!(
            self,
            Self::Read
                | Self::ReadWrite
                | Self::ReadExecute
                | Self::ReadWriteExecute
        )
    }

    /// Check if write permission is granted
    pub fn can_write(&self) -> bool {
        matches!(
            self,
            Self::Write
                | Self::ReadWrite
                | Self::WriteExecute
                | Self::ReadWriteExecute
        )
    }

    /// Check if execute permission is granted
    pub fn can_execute(&self) -> bool {
        matches!(
            self,
            Self::Execute
                | Self::ReadExecute
                | Self::WriteExecute
                | Self::ReadWriteExecute
        )
    }

    /// Get a human-readable string representation
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Read => "r--",
            Self::Write => "-w-",
            Self::Execute => "--x",
            Self::ReadWrite => "rw-",
            Self::ReadExecute => "r-x",
            Self::WriteExecute => "-wx",
            Self::ReadWriteExecute => "rwx",
            Self::None => "---",
        }
    }
}

impl fmt::Display for Protection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Memory region information
#[derive(Debug, Clone)]
pub struct MemoryRegion {
    /// Base address of the region
    pub base: u64,
    /// Size of the region in bytes
    pub size: u64,
    /// Memory protection flags
    pub protection: Protection,
    /// Name or identifier (e.g., "[stack]", "[heap]", or mapped file)
    pub name: Option<String>,
    /// Is this region a file mapping?
    pub is_file_mapping: bool,
    /// Is this a private mapping (copy-on-write)?
    pub is_private: bool,
}

impl MemoryRegion {
    /// Create a new memory region
    pub fn new(
        base: u64,
        size: u64,
        protection: Protection,
        name: Option<String>,
        is_file_mapping: bool,
        is_private: bool,
    ) -> Self {
        Self {
            base,
            size,
            protection,
            name,
            is_file_mapping,
            is_private,
        }
    }

    /// Check if an address is contained within this region
    pub fn contains(&self, address: u64) -> bool {
        address >= self.base && address < (self.base + self.size)
    }

    /// Get the address range of this region
    pub fn range(&self) -> Range<u64> {
        self.base..(self.base + self.size)
    }

    /// Get the end address of this region
    pub fn end(&self) -> u64 {
        self.base + self.size
    }
}

/// Memory map for a process
#[derive(Debug, Default)]
pub struct MemoryMap {
    /// Regions of memory
    regions: Vec<MemoryRegion>,
    /// Named memory allocations being tracked
    tracked_allocations: HashMap<String, (u64, u64)>, // (address, size)
    /// Last memory dump address
    last_address: Option<u64>,
    /// Last memory dump size
    last_size: Option<usize>,
}

impl MemoryMap {
    /// Create a new memory map
    pub fn new() -> Self {
        Self {
            regions: Vec::new(),
            tracked_allocations: HashMap::new(),
            last_address: None,
            last_size: None,
        }
    }

    /// Add a region to the memory map
    pub fn add_region(&mut self, region: MemoryRegion) {
        self.regions.push(region);
    }

    /// Find a region containing the given address
    pub fn find_region(&self, address: u64) -> Option<&MemoryRegion> {
        self.regions.iter().find(|r| r.contains(address))
    }

    /// Get all memory regions
    pub fn get_regions(&self) -> &[MemoryRegion] {
        &self.regions
    }

    /// Clear all regions
    pub fn clear(&mut self) {
        self.regions.clear();
    }

    /// Update memory regions from the process
    pub fn update_from_process(&mut self, pid: i32) -> Result<()> {
        // Clear existing regions
        self.regions.clear();
        
        // Get the task port for the target process
        let mut task: mach_port_t = 0;
        unsafe {
            let kr = task_for_pid(mach_task_self(), pid, &raw mut task);
            if kr != KERN_SUCCESS {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    format!("Failed to get task for pid {}: error {}", pid, kr)
                ));
            }
        }
        
        // Start iterating through the address space
        let mut address: mach_vm_address_t = 0;
        
        loop {
            let mut size: mach_vm_size_t = 0;
            let mut info: vm_region_basic_info_data_64_t = unsafe { std::mem::zeroed() };
            let mut count: mach_msg_type_number_t = vm_region_basic_info_data_64_t::count();
            let mut object_name: mach_port_t = 0;
            
            // Get information about the memory region at 'address'
            let kr = unsafe {
                mach_vm_region(
                    task,
                    &raw mut address,
                    &raw mut size,
                    VM_REGION_BASIC_INFO_64,
                    (&raw mut info).cast(),
                    &raw mut count,
                    &raw mut object_name
                )
            };
            
            // If we're done scanning or hit an error, break
            if kr != KERN_SUCCESS {
                break;
            }
            
            // Determine protection flags
            let protection = match (info.protection & VM_PROT_READ != 0, 
                                   info.protection & VM_PROT_WRITE != 0, 
                                   info.protection & VM_PROT_EXECUTE != 0) {
                (true, false, false) => Protection::Read,
                (false, true, false) => Protection::Write,
                (false, false, true) => Protection::Execute,
                (true, true, false) => Protection::ReadWrite,
                (true, false, true) => Protection::ReadExecute,
                (false, true, true) => Protection::WriteExecute,
                (true, true, true) => Protection::ReadWriteExecute,
                _ => Protection::None,
            };
            
            // Determine region name (this would be enhanced to show mapped files, etc)
            let name = if info.reserved != 0 {
                Some("[reserved]".to_string())
            } else if info.shared != 0 {
                Some("[shared]".to_string())
            } else {
                None
            };
            
            // Create and add the region
            let region = MemoryRegion::new(
                address,
                size,
                protection,
                name,
                false, // is_file_mapping would require additional work
                info.shared == 0, // is_private (non-shared is considered private)
            );
            
            self.add_region(region);
            
            // Move to the next region
            address += size;
        }
        
        info!("Updated memory map: {} regions found", self.regions.len());
        Ok(())
    }

    /// Get a description for an address
    pub fn describe_address(&self, address: u64) -> String {
        if let Some(region) = self.find_region(address) {
            // Check if this is a named allocation we're tracking
            for (name, (alloc_addr, alloc_size)) in &self.tracked_allocations {
                if address >= *alloc_addr && address < (*alloc_addr + *alloc_size) {
                    let offset = address - *alloc_addr;
                    return format!("{} + 0x{:x}", name, offset);
                }
            }

            // Otherwise give region-based description
            let offset = address - region.base;
            if let Some(name) = &region.name {
                return format!("{} + 0x{:x}", name, offset);
            }
            return format!("region 0x{:x} + 0x{:x}", region.base, offset);
        }

        format!("unmapped address 0x{:x}", address)
    }

    /// Track a memory allocation with a name
    pub fn track_allocation(&mut self, name: &str, address: u64, size: u64) {
        self.tracked_allocations
            .insert(name.to_string(), (address, size));
        info!("Tracking allocation {} at 0x{:x} (size: {})", name, address, size);
    }

    /// Stop tracking a memory allocation
    pub fn untrack_allocation(&mut self, name: &str) -> bool {
        let result = self.tracked_allocations.remove(name).is_some();
        if result {
            info!("Stopped tracking allocation {}", name);
        }
        result
    }

    /// Get all tracked allocations
    pub fn get_tracked_allocations(&self) -> &HashMap<String, (u64, u64)> {
        &self.tracked_allocations
    }

    /// Set the last memory dump location
    pub fn set_last_dump(&mut self, address: u64, size: usize) {
        self.last_address = Some(address);
        self.last_size = Some(size);
    }

    /// Get the last memory dump location
    pub fn get_last_dump(&self) -> Option<(u64, usize)> {
        match (self.last_address, self.last_size) {
            (Some(addr), Some(size)) => Some((addr, size)),
            _ => None,
        }
    }

    /// Format the memory data in different ways
    pub fn format_memory(&self, data: &[u8], format: MemoryFormat) -> String {
        match format {
            MemoryFormat::Hex => self.format_as_hex(data),
            MemoryFormat::Ascii => self.format_as_ascii(data),
            MemoryFormat::Utf8 => self.format_as_utf8(data),
            MemoryFormat::Disassembly => "Disassembly view in separate tab".to_string(),
            MemoryFormat::U8 => self.format_as_u8(data),
            MemoryFormat::U16 => self.format_as_u16(data),
            MemoryFormat::U32 => self.format_as_u32(data),
            MemoryFormat::U64 => self.format_as_u64(data),
            MemoryFormat::I8 => self.format_as_i8(data),
            MemoryFormat::I16 => self.format_as_i16(data),
            MemoryFormat::I32 => self.format_as_i32(data),
            MemoryFormat::I64 => self.format_as_i64(data),
            MemoryFormat::F32 => self.format_as_f32(data),
            MemoryFormat::F64 => self.format_as_f64(data),
        }
    }

    fn format_as_hex(&self, data: &[u8]) -> String {
        let mut result = String::new();
        for chunk in data.chunks(16) {
            let hex: Vec<String> = chunk.iter().map(|b| format!("{:02x}", b)).collect();
            result.push_str(&hex.join(" "));
            result.push('\n');
        }
        result
    }

    fn format_as_ascii(&self, data: &[u8]) -> String {
        let mut result = String::new();
        for chunk in data.chunks(16) {
            let ascii: String = chunk
                .iter()
                .map(|&b| {
                    if (32..=126).contains(&b) {
                        b as char
                    } else {
                        '.'
                    }
                })
                .collect();
            result.push_str(&ascii);
            result.push('\n');
        }
        result
    }

    fn format_as_utf8(&self, data: &[u8]) -> String {
        match std::str::from_utf8(data) {
            Ok(s) => s.to_string(),
            Err(_) => format!("Data is not valid UTF-8 ({} bytes)", data.len()),
        }
    }

    fn format_as_u8(&self, data: &[u8]) -> String {
        let mut result = String::new();
        for chunk in data.chunks(16) {
            let values: Vec<String> = chunk.iter().map(|&b| format!("{}", b)).collect();
            result.push_str(&values.join(" "));
            result.push('\n');
        }
        result
    }

    fn format_as_u16(&self, data: &[u8]) -> String {
        let mut result = String::new();
        for chunk in data.chunks(16).filter(|c| c.len() >= 2) {
            let mut values = Vec::new();
            for i in (0..chunk.len()).step_by(2) {
                if i + 1 < chunk.len() {
                    values.push(format!("{}", LittleEndian::read_u16(&chunk[i..i+2])));
                }
            }
            result.push_str(&values.join(" "));
            result.push('\n');
        }
        result
    }

    fn format_as_u32(&self, data: &[u8]) -> String {
        let mut result = String::new();
        for chunk in data.chunks(16).filter(|c| c.len() >= 4) {
            let mut values = Vec::new();
            for i in (0..chunk.len()).step_by(4) {
                if i + 3 < chunk.len() {
                    values.push(format!("{}", LittleEndian::read_u32(&chunk[i..i+4])));
                }
            }
            result.push_str(&values.join(" "));
            result.push('\n');
        }
        result
    }

    fn format_as_u64(&self, data: &[u8]) -> String {
        let mut result = String::new();
        for chunk in data.chunks(16).filter(|c| c.len() >= 8) {
            let mut values = Vec::new();
            for i in (0..chunk.len()).step_by(8) {
                if i + 7 < chunk.len() {
                    values.push(format!("{}", LittleEndian::read_u64(&chunk[i..i+8])));
                }
            }
            result.push_str(&values.join(" "));
            result.push('\n');
        }
        result
    }

    fn format_as_i8(&self, data: &[u8]) -> String {
        let mut result = String::new();
        for chunk in data.chunks(16) {
            let values: Vec<String> = chunk.iter().map(|&b| format!("{}", b as i8)).collect();
            result.push_str(&values.join(" "));
            result.push('\n');
        }
        result
    }

    fn format_as_i16(&self, data: &[u8]) -> String {
        let mut result = String::new();
        for chunk in data.chunks(16).filter(|c| c.len() >= 2) {
            let mut values = Vec::new();
            for i in (0..chunk.len()).step_by(2) {
                if i + 1 < chunk.len() {
                    values.push(format!("{}", LittleEndian::read_i16(&chunk[i..i+2])));
                }
            }
            result.push_str(&values.join(" "));
            result.push('\n');
        }
        result
    }

    fn format_as_i32(&self, data: &[u8]) -> String {
        let mut result = String::new();
        for chunk in data.chunks(16).filter(|c| c.len() >= 4) {
            let mut values = Vec::new();
            for i in (0..chunk.len()).step_by(4) {
                if i + 3 < chunk.len() {
                    values.push(format!("{}", LittleEndian::read_i32(&chunk[i..i+4])));
                }
            }
            result.push_str(&values.join(" "));
            result.push('\n');
        }
        result
    }

    fn format_as_i64(&self, data: &[u8]) -> String {
        let mut result = String::new();
        for chunk in data.chunks(16).filter(|c| c.len() >= 8) {
            let mut values = Vec::new();
            for i in (0..chunk.len()).step_by(8) {
                if i + 7 < chunk.len() {
                    values.push(format!("{}", LittleEndian::read_i64(&chunk[i..i+8])));
                }
            }
            result.push_str(&values.join(" "));
            result.push('\n');
        }
        result
    }

    fn format_as_f32(&self, data: &[u8]) -> String {
        let mut result = String::new();
        for chunk in data.chunks(16).filter(|c| c.len() >= 4) {
            let mut values = Vec::new();
            for i in (0..chunk.len()).step_by(4) {
                if i + 3 < chunk.len() {
                    values.push(format!("{:.6}", LittleEndian::read_f32(&chunk[i..i+4])));
                }
            }
            result.push_str(&values.join(" "));
            result.push('\n');
        }
        result
    }

    fn format_as_f64(&self, data: &[u8]) -> String {
        let mut result = String::new();
        for chunk in data.chunks(16).filter(|c| c.len() >= 8) {
            let mut values = Vec::new();
            for i in (0..chunk.len()).step_by(8) {
                if i + 7 < chunk.len() {
                    values.push(format!("{:.6}", LittleEndian::read_f64(&chunk[i..i+8])));
                }
            }
            result.push_str(&values.join(" "));
            result.push('\n');
        }
        result
    }

    /// Search memory for a pattern
    pub fn search_memory(&self, memory_data: &[u8], base_address: u64, pattern: &SearchPattern) -> Vec<SearchResult> {
        let mut results = Vec::new();
        
        match pattern {
            SearchPattern::Bytes(bytes) => {
                // Simple byte pattern search
                for (i, window) in memory_data.windows(bytes.len()).enumerate() {
                    if window == bytes.as_slice() {
                        let match_address = base_address + i as u64;
                        let result = self.create_search_result(memory_data, match_address, i, bytes.len());
                        results.push(result);
                    }
                }
            },
            SearchPattern::Text(text) => {
                let bytes = text.as_bytes();
                for (i, window) in memory_data.windows(bytes.len()).enumerate() {
                    if window == bytes {
                        let match_address = base_address + i as u64;
                        let result = self.create_search_result(memory_data, match_address, i, bytes.len());
                        results.push(result);
                    }
                }
            },
            SearchPattern::TextIgnoreCase(text) => {
                let lower_text = text.to_lowercase();
                let bytes = lower_text.as_bytes();
                for (i, window) in memory_data.windows(bytes.len()).enumerate() {
                    // Convert window to lowercase for comparison
                    let mut window_lower = Vec::with_capacity(window.len());
                    for &b in window {
                        if b.is_ascii_uppercase() {
                            window_lower.push(b.to_ascii_lowercase());
                        } else {
                            window_lower.push(b);
                        }
                    }
                    if window_lower == bytes {
                        let match_address = base_address + i as u64;
                        let result = self.create_search_result(memory_data, match_address, i, bytes.len());
                        results.push(result);
                    }
                }
            },
            SearchPattern::Integer(value, width) => {
                // Search for integer of specific width
                match width {
                    1 => {
                        let byte_val = *value as u8;
                        for (i, &b) in memory_data.iter().enumerate() {
                            if b == byte_val {
                                let match_address = base_address + i as u64;
                                let result = self.create_search_result(memory_data, match_address, i, 1);
                                results.push(result);
                            }
                        }
                    },
                    2 => {
                        let val = *value as u16;
                        for (i, chunk) in memory_data.windows(2).enumerate() {
                            if LittleEndian::read_u16(chunk) == val {
                                let match_address = base_address + i as u64;
                                let result = self.create_search_result(memory_data, match_address, i, 2);
                                results.push(result);
                            }
                        }
                    },
                    4 => {
                        let val = *value as u32;
                        for (i, chunk) in memory_data.windows(4).enumerate() {
                            if LittleEndian::read_u32(chunk) == val {
                                let match_address = base_address + i as u64;
                                let result = self.create_search_result(memory_data, match_address, i, 4);
                                results.push(result);
                            }
                        }
                    },
                    8 => {
                        let val = *value;
                        for (i, chunk) in memory_data.windows(8).enumerate() {
                            if LittleEndian::read_u64(chunk) == val {
                                let match_address = base_address + i as u64;
                                let result = self.create_search_result(memory_data, match_address, i, 8);
                                results.push(result);
                            }
                        }
                    },
                    _ => {
                        // Unsupported width
                    }
                }
            },
            SearchPattern::Float(value, width) => {
                // Search for float of specific width
                match width {
                    4 => {
                        let val = *value as f32;
                        for (i, chunk) in memory_data.windows(4).enumerate() {
                            let float_val = LittleEndian::read_f32(chunk);
                            if (float_val - val).abs() < f32::EPSILON {
                                let match_address = base_address + i as u64;
                                let result = self.create_search_result(memory_data, match_address, i, 4);
                                results.push(result);
                            }
                        }
                    },
                    8 => {
                        let val = *value;
                        for (i, chunk) in memory_data.windows(8).enumerate() {
                            let float_val = LittleEndian::read_f64(chunk);
                            if (float_val - val).abs() < f64::EPSILON {
                                let match_address = base_address + i as u64;
                                let result = self.create_search_result(memory_data, match_address, i, 8);
                                results.push(result);
                            }
                        }
                    },
                    _ => {
                        // Unsupported width
                    }
                }
            }
        }
        
        results
    }
    
    /// Find the next memory region after the given address
    pub fn find_next_region(&self, current_address: u64) -> Option<&MemoryRegion> {
        self.regions
            .iter()
            .filter(|r| r.base > current_address)
            .min_by_key(|r| r.base)
    }
    
    /// Find the previous memory region before the given address
    pub fn find_prev_region(&self, current_address: u64) -> Option<&MemoryRegion> {
        self.regions
            .iter()
            .filter(|r| r.base < current_address)
            .max_by_key(|r| r.base)
    }
    
    /// Find all executable regions (potential code)
    pub fn find_executable_regions(&self) -> Vec<&MemoryRegion> {
        self.regions
            .iter()
            .filter(|r| r.protection.can_execute())
            .collect()
    }

    /// Find all stack regions
    pub fn find_stack_regions(&self) -> Vec<&MemoryRegion> {
        self.regions
            .iter()
            .filter(|r| r.name.as_ref().is_some_and(|n| n.contains("stack")))
            .collect()
    }

    /// Find all heap regions
    pub fn find_heap_regions(&self) -> Vec<&MemoryRegion> {
        self.regions
            .iter()
            .filter(|r| r.name.as_ref().is_some_and(|n| n.contains("heap")))
            .collect()
    }
    
    /// Create a search result with context
    fn create_search_result(&self, data: &[u8], match_address: u64, match_index: usize, match_len: usize) -> SearchResult {
        // Create a context window around the match (16 bytes before and after)
        const CONTEXT_SIZE: usize = 16;
        let start_idx = match_index.saturating_sub(CONTEXT_SIZE);
        let end_idx = min(match_index + match_len + CONTEXT_SIZE, data.len());
        
        let context = data[start_idx..end_idx].to_vec();
        let match_range = (match_index - start_idx)..(match_index - start_idx + match_len);
        
        // Find the memory region for this address
        let region_name = self.find_region(match_address)
            .and_then(|r| r.name.clone());
        
        SearchResult {
            address: match_address,
            context,
            match_range,
            region_name,
        }
    }
    
    /// Parse a value from a memory buffer at an offset
    pub fn parse_value(&self, data: &[u8], offset: usize, format: MemoryFormat) -> AnyhowResult<String> {
        if offset >= data.len() {
            return Err(anyhow!("Offset {} out of bounds (data length: {})", offset, data.len()));
        }
        
        match format {
            MemoryFormat::U8 => {
                if offset < data.len() {
                    Ok(format!("{}", data[offset]))
                } else {
                    Err(anyhow!("Invalid data offset for u8"))
                }
            },
            MemoryFormat::I8 => {
                if offset < data.len() {
                    Ok(format!("{}", data[offset] as i8))
                } else {
                    Err(anyhow!("Invalid data offset for i8"))
                }
            },
            MemoryFormat::U16 => {
                if offset + 1 < data.len() {
                    Ok(format!("{}", LittleEndian::read_u16(&data[offset..])))
                } else {
                    Err(anyhow!("Invalid data offset for u16"))
                }
            },
            MemoryFormat::I16 => {
                if offset + 1 < data.len() {
                    Ok(format!("{}", LittleEndian::read_i16(&data[offset..])))
                } else {
                    Err(anyhow!("Invalid data offset for i16"))
                }
            },
            MemoryFormat::U32 => {
                if offset + 3 < data.len() {
                    Ok(format!("{}", LittleEndian::read_u32(&data[offset..])))
                } else {
                    Err(anyhow!("Invalid data offset for u32"))
                }
            },
            MemoryFormat::I32 => {
                if offset + 3 < data.len() {
                    Ok(format!("{}", LittleEndian::read_i32(&data[offset..])))
                } else {
                    Err(anyhow!("Invalid data offset for i32"))
                }
            },
            MemoryFormat::U64 => {
                if offset + 7 < data.len() {
                    Ok(format!("{}", LittleEndian::read_u64(&data[offset..])))
                } else {
                    Err(anyhow!("Invalid data offset for u64"))
                }
            },
            MemoryFormat::I64 => {
                if offset + 7 < data.len() {
                    Ok(format!("{}", LittleEndian::read_i64(&data[offset..])))
                } else {
                    Err(anyhow!("Invalid data offset for i64"))
                }
            },
            MemoryFormat::F32 => {
                if offset + 3 < data.len() {
                    Ok(format!("{:.6}", LittleEndian::read_f32(&data[offset..])))
                } else {
                    Err(anyhow!("Invalid data offset for f32"))
                }
            },
            MemoryFormat::F64 => {
                if offset + 7 < data.len() {
                    Ok(format!("{:.6}", LittleEndian::read_f64(&data[offset..])))
                } else {
                    Err(anyhow!("Invalid data offset for f64"))
                }
            },
            MemoryFormat::Hex => {
                if offset < data.len() {
                    Ok(format!("{:02x}", data[offset]))
                } else {
                    Err(anyhow!("Invalid data offset for hex"))
                }
            },
            MemoryFormat::Ascii => {
                if offset < data.len() {
                    let ch = if (32..=126).contains(&data[offset]) {
                        data[offset] as char
                    } else {
                        '.'
                    };
                    Ok(format!("{}", ch))
                } else {
                    Err(anyhow!("Invalid data offset for ASCII"))
                }
            },
            MemoryFormat::Utf8 => {
                if offset < data.len() {
                    let mut end = offset + 1;
                    while end < data.len() && (data[end] & 0xC0) == 0x80 {
                        end += 1;
                    }
                    
                    match std::str::from_utf8(&data[offset..end]) {
                        Ok(s) => Ok(s.to_string()),
                        Err(_) => Ok(".".to_string()),
                    }
                } else {
                    Err(anyhow!("Invalid data offset for UTF-8"))
                }
            },
            MemoryFormat::Disassembly => {
                Err(anyhow!("Disassembly format requires a special handler"))
            },
        }
    }
}

/// Memory format for display
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryFormat {
    /// Hexadecimal bytes
    Hex,
    /// ASCII representation
    Ascii,
    /// UTF-8 representation
    Utf8,
    /// Disassembled instructions
    Disassembly,
    /// Unsigned 8-bit integers
    U8,
    /// Unsigned 16-bit integers
    U16,
    /// Unsigned 32-bit integers
    U32,
    /// Unsigned 64-bit integers
    U64,
    /// Signed 8-bit integers
    I8,
    /// Signed 16-bit integers
    I16,
    /// Signed 32-bit integers
    I32,
    /// Signed 64-bit integers
    I64,
    /// 32-bit floating point
    F32,
    /// 64-bit floating point
    F64,
}

impl MemoryFormat {
    /// Get all available memory formats
    pub fn all() -> Vec<Self> {
        vec![
            Self::Hex,
            Self::Ascii,
            Self::Utf8,
            Self::Disassembly,
            Self::U8,
            Self::U16,
            Self::U32,
            Self::U64,
            Self::I8,
            Self::I16,
            Self::I32,
            Self::I64,
            Self::F32,
            Self::F64,
        ]
    }
    
    /// Convert to string representation
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Hex => "Hex",
            Self::Ascii => "ASCII",
            Self::Utf8 => "UTF-8",
            Self::Disassembly => "Disassembly",
            Self::U8 => "u8",
            Self::U16 => "u16",
            Self::U32 => "u32",
            Self::U64 => "u64",
            Self::I8 => "i8",
            Self::I16 => "i16",
            Self::I32 => "i32",
            Self::I64 => "i64",
            Self::F32 => "f32",
            Self::F64 => "f64",
        }
    }

    pub fn format_value(&self, data: &[u8]) -> String {
        match self {
            Self::Hex => Self::format_as_hex(data),
            Self::I32 => Self::format_as_i32(data),
            Self::I64 => Self::format_as_i64(data),
            Self::F32 => Self::format_as_f32(data),
            Self::F64 => Self::format_as_f64(data),
            // Handle the missing variants
            Self::Ascii => "Ascii format not implemented yet".to_string(),
            Self::Utf8 => "UTF-8 format not implemented yet".to_string(),
            Self::Disassembly => "Disassembly format not implemented yet".to_string(),
            Self::U8 => "U8 format not implemented yet".to_string(),
            Self::U16 => "U16 format not implemented yet".to_string(),
            Self::U32 => "U32 format not implemented yet".to_string(),
            Self::U64 => "U64 format not implemented yet".to_string(),
            Self::I8 => "I8 format not implemented yet".to_string(),
            Self::I16 => "I16 format not implemented yet".to_string(),
        }
    }
    
    pub fn next(&self) -> Self {
        match self {
            Self::Hex => Self::I32,
            Self::I32 => Self::I64,
            Self::I64 => Self::F32,
            Self::F32 => Self::F64,
            Self::F64 => Self::Hex,
            // Handle the missing variants
            Self::Ascii => Self::Utf8,
            Self::Utf8 => Self::Disassembly,
            Self::Disassembly => Self::U8,
            Self::U8 => Self::U16,
            Self::U16 => Self::U32,
            Self::U32 => Self::U64,
            Self::U64 => Self::I8,
            Self::I8 => Self::I16,
            Self::I16 => Self::Hex,
        }
    }
    
    fn format_as_hex(data: &[u8]) -> String {
        let mut result = String::new();
        for chunk in data.chunks(16) {
            let hex: Vec<String> = chunk.iter().map(|b| format!("{:02x}", b)).collect();
            result.push_str(&hex.join(" "));
            result.push('\n');
        }
        result
    }

    fn format_as_i32(data: &[u8]) -> String {
        let mut result = String::new();
        for chunk in data.chunks(16).filter(|c| c.len() >= 4) {
            let mut values = Vec::new();
            for i in (0..chunk.len()).step_by(4) {
                if i + 3 < chunk.len() {
                    values.push(format!("{}", LittleEndian::read_i32(&chunk[i..i+4])));
                }
            }
            result.push_str(&values.join(" "));
            result.push('\n');
        }
        result
    }

    fn format_as_i64(data: &[u8]) -> String {
        let mut result = String::new();
        for chunk in data.chunks(16).filter(|c| c.len() >= 8) {
            let mut values = Vec::new();
            for i in (0..chunk.len()).step_by(8) {
                if i + 7 < chunk.len() {
                    values.push(format!("{}", LittleEndian::read_i64(&chunk[i..i+8])));
                }
            }
            result.push_str(&values.join(" "));
            result.push('\n');
        }
        result
    }

    fn format_as_f32(data: &[u8]) -> String {
        let mut result = String::new();
        for chunk in data.chunks(16).filter(|c| c.len() >= 4) {
            let mut values = Vec::new();
            for i in (0..chunk.len()).step_by(4) {
                if i + 3 < chunk.len() {
                    values.push(format!("{:.6}", LittleEndian::read_f32(&chunk[i..i+4])));
                }
            }
            result.push_str(&values.join(" "));
            result.push('\n');
        }
        result
    }

    fn format_as_f64(data: &[u8]) -> String {
        let mut result = String::new();
        for chunk in data.chunks(16).filter(|c| c.len() >= 8) {
            let mut values = Vec::new();
            for i in (0..chunk.len()).step_by(8) {
                if i + 7 < chunk.len() {
                    values.push(format!("{:.6}", LittleEndian::read_f64(&chunk[i..i+8])));
                }
            }
            result.push_str(&values.join(" "));
            result.push('\n');
        }
        result
    }
}
