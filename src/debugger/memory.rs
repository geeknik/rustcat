use std::collections::HashMap;
use std::fmt;
use std::ops::Range;

use anyhow::{anyhow, Result};
use log::{debug, info};
use byteorder::{ByteOrder, LittleEndian, BigEndian};

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
            Protection::Read
                | Protection::ReadWrite
                | Protection::ReadExecute
                | Protection::ReadWriteExecute
        )
    }

    /// Check if write permission is granted
    pub fn can_write(&self) -> bool {
        matches!(
            self,
            Protection::Write
                | Protection::ReadWrite
                | Protection::WriteExecute
                | Protection::ReadWriteExecute
        )
    }

    /// Check if execute permission is granted
    pub fn can_execute(&self) -> bool {
        matches!(
            self,
            Protection::Execute
                | Protection::ReadExecute
                | Protection::WriteExecute
                | Protection::ReadWriteExecute
        )
    }

    /// Get a human-readable string representation
    pub fn as_str(&self) -> &'static str {
        match self {
            Protection::Read => "r--",
            Protection::Write => "-w-",
            Protection::Execute => "--x",
            Protection::ReadWrite => "rw-",
            Protection::ReadExecute => "r-x",
            Protection::WriteExecute => "-wx",
            Protection::ReadWriteExecute => "rwx",
            Protection::None => "---",
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
    pub fn update_from_process(&mut self, _pid: i32) -> Result<()> {
        // This will be implemented using platform-specific code
        // For macOS, we'll use task_for_pid and mach_vm_region_recurse
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
            } else {
                return format!("region 0x{:x} + 0x{:x}", region.base, offset);
            }
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
                    if b >= 32 && b <= 126 {
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
    pub fn all() -> Vec<MemoryFormat> {
        vec![
            MemoryFormat::Hex,
            MemoryFormat::Ascii,
            MemoryFormat::Utf8,
            MemoryFormat::Disassembly,
            MemoryFormat::U8,
            MemoryFormat::U16,
            MemoryFormat::U32,
            MemoryFormat::U64,
            MemoryFormat::I8,
            MemoryFormat::I16,
            MemoryFormat::I32,
            MemoryFormat::I64,
            MemoryFormat::F32,
            MemoryFormat::F64,
        ]
    }
    
    /// Convert to string representation
    pub fn as_str(&self) -> &'static str {
        match self {
            MemoryFormat::Hex => "Hex",
            MemoryFormat::Ascii => "ASCII",
            MemoryFormat::Utf8 => "UTF-8",
            MemoryFormat::Disassembly => "Disassembly",
            MemoryFormat::U8 => "u8",
            MemoryFormat::U16 => "u16",
            MemoryFormat::U32 => "u32",
            MemoryFormat::U64 => "u64",
            MemoryFormat::I8 => "i8",
            MemoryFormat::I16 => "i16",
            MemoryFormat::I32 => "i32",
            MemoryFormat::I64 => "i64",
            MemoryFormat::F32 => "f32",
            MemoryFormat::F64 => "f64",
        }
    }
}
