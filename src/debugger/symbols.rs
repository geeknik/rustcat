use std::collections::BTreeMap;
use std::path::Path;
use std::collections::HashMap;

use anyhow::{anyhow, Result};
use goblin::Object;
use log::{debug, warn, info};
use cpp_demangle::Symbol as CppSymbol;
// We'll use the cpp_demangle crate for Rust symbols too until we add rustc_demangle
// use rustc_demangle::demangle as rust_demangle;

/// Symbol type classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SymbolType {
    /// Function
    Function,
    /// Global variable
    GlobalVariable,
    /// Static variable
    StaticVariable,
    /// Text section (code)
    Text,
    /// Data section
    Data,
    /// Debug symbol
    Debug,
    /// Other/unknown
    Other,
}

impl SymbolType {
    /// Convert to string representation
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Function => "Function",
            Self::GlobalVariable => "Global Variable",
            Self::StaticVariable => "Static Variable",
            Self::Text => "Text Section",
            Self::Data => "Data Section",
            Self::Debug => "Debug Symbol",
            Self::Other => "Other",
        }
    }
}

/// Programming language of the symbol
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Language {
    /// C language
    C,
    /// C++ language
    Cpp,
    /// Rust language
    Rust,
    /// Swift language
    Swift,
    /// Objective-C language
    ObjectiveC,
    /// Unknown language
    Unknown,
}

impl Language {
    /// Convert to string representation
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::C => "C",
            Self::Cpp => "C++",
            Self::Rust => "Rust",
            Self::Swift => "Swift",
            Self::ObjectiveC => "Objective-C",
            Self::Unknown => "Unknown",
        }
    }
    
    /// Detect language from symbol name
    pub fn detect_from_name(name: &str) -> Self {
        if name.starts_with("_Z") || name.starts_with("__Z") {
            // Itanium C++ ABI mangling
            Self::Cpp
        } else if name.starts_with("__") && name.contains("$_") {
            // Microsoft Visual C++ mangling
            Self::Cpp
        } else if name.starts_with("_R") {
            // Rust symbol mangling
            Self::Rust
        } else if name.starts_with("__swift") {
            // Swift symbols
            Self::Swift
        } else if name.starts_with("+[") || name.starts_with("-[") {
            // Objective-C method
            Self::ObjectiveC
        } else {
            // Default to C
            Self::C
        }
    }
}

/// Represents a symbol in the binary
#[derive(Debug, Clone)]
pub struct Symbol {
    /// Symbol name
    name: String,
    /// Demangled name (if applicable)
    demangled_name: Option<String>,
    /// Memory address
    address: u64,
    /// Symbol size (if known)
    size: Option<u64>,
    /// Symbol type
    symbol_type: SymbolType,
    /// Source file (if known)
    source_file: Option<String>,
    /// Line number (if known)
    line: Option<u32>,
    /// Symbol visibility (public, private, etc.)
    visibility: Option<String>,
    /// Section name (if known)
    section: Option<String>,
    /// Language (C, C++, Rust, etc.)
    language: Option<Language>,
    /// Symbol binding (local, global, weak)
    binding: Option<String>,
}

impl Symbol {
    /// Create a new symbol
    pub fn new(
        name: String,
        address: u64,
        size: Option<u64>,
        symbol_type: SymbolType,
        source_file: Option<String>,
        line: Option<u32>,
        visibility: Option<String>,
    ) -> Self {
        // Detect language from symbol name
        let language = Language::detect_from_name(&name);
        
        // Try to demangle based on detected language
        let demangled_name = match language {
            Language::Cpp => {
                if name.starts_with("_Z") || name.starts_with("__Z") {
                    // This looks like a mangled C++ name (Itanium ABI), try to demangle it
                    let mangled_part = if name.starts_with("__Z") { &name[1..] } else { &name };
                    match CppSymbol::new(mangled_part) {
                        Ok(demangled) => Some(demangled.to_string()),
                        Err(_) => None,
                    }
                } else if name.starts_with("?") {
                    // Microsoft Visual C++ mangling
                    // Note: We would need a MSVC demangler here
                    // For now, we'll just return None
                    None
                } else {
                    None
                }
            },
            Language::Rust => {
                // For Rust symbols, we'd typically use rustc_demangle
                // But for now, we'll just leave the name as is
                // We'll add proper Rust demangling in a future update
                None
            },
            _ => None,
        };
        
        Self {
            name,
            demangled_name,
            address,
            size,
            symbol_type,
            source_file,
            line,
            visibility,
            section: None,
            language: Some(language),
            binding: None,
        }
    }
    
    /// Create a new symbol with additional information
    pub fn new_with_details(
        name: String,
        address: u64,
        size: Option<u64>,
        symbol_type: SymbolType,
        source_file: Option<String>,
        line: Option<u32>,
        visibility: Option<String>,
        section: Option<String>,
        binding: Option<String>,
    ) -> Self {
        // Create basic symbol first
        let mut symbol = Self::new(
            name,
            address,
            size,
            symbol_type,
            source_file,
            line,
            visibility,
        );
        
        // Add additional details
        symbol.section = section;
        symbol.binding = binding;
        
        symbol
    }
    
    /// Get the symbol name
    pub fn name(&self) -> &str {
        &self.name
    }
    
    /// Get the demangled name if available, otherwise the raw name
    pub fn display_name(&self) -> &str {
        if let Some(demangled) = &self.demangled_name {
            demangled
        } else {
            &self.name
        }
    }
    
    /// Get the symbol address
    pub fn address(&self) -> u64 {
        self.address
    }
    
    /// Get the symbol size
    pub fn size(&self) -> Option<u64> {
        self.size
    }
    
    /// Check if the symbol is a function
    pub fn is_function(&self) -> bool {
        self.symbol_type == SymbolType::Function
    }
    
    /// Get the symbol type
    pub fn symbol_type(&self) -> SymbolType {
        self.symbol_type
    }
    
    /// Get the source file
    pub fn source_file(&self) -> Option<&str> {
        self.source_file.as_deref()
    }
    
    /// Get the line number
    pub fn line(&self) -> Option<u32> {
        self.line
    }
    
    /// Get the symbol visibility
    pub fn visibility(&self) -> Option<&str> {
        self.visibility.as_deref()
    }
    
    /// Get the section name
    pub fn section(&self) -> Option<&str> {
        self.section.as_deref()
    }
    
    /// Get the symbol language
    pub fn language(&self) -> Option<Language> {
        self.language
    }
    
    /// Get the binding type
    pub fn binding(&self) -> Option<&str> {
        self.binding.as_deref()
    }
    
    /// Set the section name
    pub fn set_section(&mut self, section: Option<String>) {
        self.section = section;
    }
    
    /// Set the binding type
    pub fn set_binding(&mut self, binding: Option<String>) {
        self.binding = binding;
    }
}

/// Represents a section in the binary
#[derive(Debug, Clone)]
pub struct Section {
    /// Section name
    pub name: String,
    /// Section address
    pub address: u64,
    /// Section size
    pub size: u64,
    /// Section flags
    pub flags: u64,
    /// Is this section executable?
    pub is_executable: bool,
    /// Is this section writable?
    pub is_writable: bool,
    /// Is this section in memory?
    pub is_allocated: bool,
}

impl Section {
    /// Create a new section
    pub fn new(name: String, address: u64, size: u64, flags: u64) -> Self {
        // Determine section attributes based on flags
        // These flags are different for each binary format
        // For simplicity, we'll just check if certain bits are set
        // In a real implementation, we'd have format-specific logic
        let is_executable = (flags & 0x1) != 0;
        let is_writable = (flags & 0x2) != 0;
        let is_allocated = (flags & 0x4) != 0;
        
        Self {
            name,
            address,
            size,
            flags,
            is_executable,
            is_writable,
            is_allocated,
        }
    }
    
    /// Check if an address is within this section
    pub fn contains(&self, address: u64) -> bool {
        address >= self.address && address < (self.address + self.size)
    }
    
    /// Get a human-readable description of the section
    pub fn description(&self) -> String {
        let mut attributes = Vec::new();
        
        if self.is_executable {
            attributes.push("execute");
        }
        
        if self.is_writable {
            attributes.push("write");
        }
        
        if self.is_allocated {
            attributes.push("alloc");
        }
        
        format!(
            "{}: 0x{:x}-0x{:x} ({} bytes) [{}]",
            self.name,
            self.address,
            self.address + self.size,
            self.size,
            attributes.join(", ")
        )
    }
}

/// Symbol table for the target program
pub struct SymbolTable {
    /// Symbols by address
    by_address: BTreeMap<u64, Symbol>,
    /// Symbols by name
    by_name: BTreeMap<String, u64>,
    /// Demangled names to address mapping
    by_demangled_name: BTreeMap<String, u64>,
    /// Address range index for fast range lookup
    address_ranges: Vec<(u64, u64, u64)>,  // (start, end, symbol_address)
    /// Symbol name prefix index for autocomplete
    name_prefix_index: BTreeMap<String, Vec<u64>>,
    /// Loading progress
    loading_progress: Option<f32>,
    /// Loading status
    loading_status: String,
    /// Target architecture
    architecture: Option<String>,
    /// Binary format
    binary_format: Option<String>,
    /// Sections in the binary
    sections: Vec<Section>,
    /// Symbol count by type
    symbol_counts: HashMap<SymbolType, usize>,
}

impl SymbolTable {
    /// Create a new empty symbol table
    pub fn new() -> Self {
        Self {
            by_address: BTreeMap::new(),
            by_name: BTreeMap::new(),
            by_demangled_name: BTreeMap::new(),
            address_ranges: Vec::new(),
            name_prefix_index: BTreeMap::new(),
            loading_progress: None,
            loading_status: "Not loaded".to_string(),
            architecture: None,
            binary_format: None,
            sections: Vec::new(),
            symbol_counts: HashMap::new(),
        }
    }
    
    /// Load symbols from a file
    pub fn load_from_file<P: AsRef<Path>>(&mut self, path: P) -> Result<()> {
        // Clear existing symbols and state
        self.by_address.clear();
        self.by_name.clear();
        self.by_demangled_name.clear();
        self.address_ranges.clear();
        self.name_prefix_index.clear();
        self.sections.clear();
        self.symbol_counts.clear();
        
        self.loading_progress = Some(0.0);
        self.loading_status = "Loading file...".to_string();
        
        // Read the file
        let data = std::fs::read(path.as_ref())?;
        
        self.loading_progress = Some(0.1);
        self.loading_status = "Parsing binary...".to_string();
        
        // Parse the binary
        let binary = Object::parse(&data)?;
        match binary {
            Object::Mach(mach_obj) => {
                self.binary_format = Some("Mach-O".to_string());
                // We need to handle both fat and non-fat Mach-O binaries
                match mach_obj {
                    goblin::mach::Mach::Binary(mach_binary) => {
                        self.architecture = Some(Self::cpu_type_to_arch(mach_binary.header.cputype));
                        self.load_macho_symbols(&mach_binary)?;
                    },
                    goblin::mach::Mach::Fat(fat) => {
                        // For fat binaries, find the ARM64 slice
                        for i in 0..fat.narches {
                            // Use direct get method to retrieve slice
                            if let Ok(goblin::mach::SingleArch::MachO(mach_binary)) = fat.get(i) {
                                // CPU_TYPE_ARM64 == 0x100000C
                                if mach_binary.header.cputype == 0x0100_000C {
                                    self.architecture = Some("arm64".to_string());
                                    self.load_macho_symbols(&mach_binary)?;
                                    break;
                                }
                            }
                        }
                    }
                }
            },
            Object::Elf(elf) => {
                self.binary_format = Some("ELF".to_string());
                self.architecture = Some(Self::elf_machine_to_arch(elf.header.e_machine));
                self.load_elf_symbols(&elf)?;
            },
            Object::PE(pe) => {
                self.binary_format = Some("PE".to_string());
                self.architecture = Some(Self::pe_machine_to_arch(pe.header.coff_header.machine));
                warn!("PE symbol loading not fully implemented yet");
                // self.load_pe_symbols(&pe)?;
            },
            _ => return Err(anyhow!("Unsupported binary format")),
        }
        
        // Log symbol statistics
        info!("Loaded {} symbols from {}", self.by_address.len(), path.as_ref().display());
        for (symbol_type, count) in &self.symbol_counts {
            info!("  {}: {}", symbol_type.as_str(), count);
        }
        
        info!("Found {} sections", self.sections.len());
        let exec_sections = self.sections.iter().filter(|s| s.is_executable).count();
        info!("  Executable sections: {}", exec_sections);
        
        self.loading_progress = Some(1.0);
        self.loading_status = format!("Loaded {} symbols", self.by_address.len());
        
        Ok(())
    }
    
    /// Convert COFF machine type to architecture string
    fn pe_machine_to_arch(machine: u16) -> String {
        match machine {
            0x014c => "x86".to_string(),
            0x8664 => "x86_64".to_string(),
            0x01c4 => "arm".to_string(),
            0xaa64 => "arm64".to_string(),
            _ => format!("unknown (0x{:x})", machine),
        }
    }
    
    /// Convert ELF machine type to architecture string
    fn elf_machine_to_arch(machine: u16) -> String {
        match machine {
            3 => "x86".to_string(),
            62 => "x86_64".to_string(),
            40 => "arm".to_string(),
            183 => "arm64".to_string(),
            _ => format!("unknown ({})", machine),
        }
    }
    
    /// Convert Mach-O CPU type to architecture string
    fn cpu_type_to_arch(cputype: u32) -> String {
        match cputype {
            7 => "x86".to_string(),
            0x0100_0007 => "x86_64".to_string(),
            12 => "arm".to_string(),
            0x0100_000C => "arm64".to_string(),
            _ => format!("unknown (0x{:x})", cputype),
        }
    }
    
    /// Load symbols from a Mach-O binary
    fn load_macho_symbols(&mut self, macho: &goblin::mach::MachO) -> Result<()> {
        self.loading_progress = Some(0.2);
        self.loading_status = "Loading Mach-O symbols...".to_string();
        
        // Load sections first
        self.loading_progress = Some(0.3);
        self.loading_status = "Loading Mach-O sections...".to_string();
        
        // Process sections from each segment
        for segment in &macho.segments {
            debug!("Processing segment: {} (sections: {})", segment.name()?, segment.nsects);
            
            for section_result in segment.sections()? {
                if let Ok((section_header, _)) = section_result {
                    let name = section_header.name()?;
                    let address = section_header.addr as u64;
                    let size = section_header.size;
                    
                    // Parse flags to determine section attributes
                    let flags = section_header.flags as u64;
                    
                    // Add to our section list
                    self.sections.push(Section::new(
                        name.to_string(),
                        address,
                        size,
                        flags
                    ));
                    
                    debug!("Added section: {} at 0x{:x} ({} bytes)", name, address, size);
                }
            }
        }
        
        // Load symbols from symbol table
        self.loading_progress = Some(0.4);
        self.loading_status = "Loading Mach-O symbols...".to_string();
        
        // We can't directly get the count of symbols, so we'll process them without a progress update
        for symbol_result in macho.symbols.iter() {
            if let Ok((name, nlist)) = symbol_result {
                // Skip some system symbols
                if name.starts_with("__") || name.is_empty() {
                    continue;
                }
                
                let address = nlist.n_value;
                
                // Determine symbol type
                let symbol_type = match nlist.n_type & 0x0e {  // Type mask
                    0x0e => SymbolType::Function,  // N_SECT with N_EXT in TEXT section
                    0x02 => SymbolType::GlobalVariable,  // N_EXT with no N_SECT
                    _ => {
                        // If in a text section, likely a function
                        if let Some(section_idx) = nlist.get_sect_idx() {
                            if section_idx > 0 && section_idx <= self.sections.len() as u8 {
                                let section = &self.sections[section_idx as usize - 1];
                                if section.is_executable {
                                    SymbolType::Function
                                } else {
                                    SymbolType::Data
                                }
                            } else {
                                SymbolType::Other
                            }
                        } else {
                            SymbolType::Other
                        }
                    }
                };
                
                // Determine visibility
                let visibility = if (nlist.n_type & 0x01) != 0 {  // N_EXT bit
                    Some("global".to_string())
                } else {
                    Some("local".to_string())
                };
                
                // Get section name
                let section_name = if let Some(section_idx) = nlist.get_sect_idx() {
                    if section_idx > 0 && section_idx <= self.sections.len() as u8 {
                        Some(self.sections[section_idx as usize - 1].name.clone())
                    } else {
                        None
                    }
                } else {
                    None
                };
                
                // Determine binding
                let binding = if (nlist.n_desc & 0x10) != 0 {  // N_WEAK_REF bit
                    Some("weak".to_string())
                } else if (nlist.n_type & 0x01) != 0 {  // N_EXT bit
                    Some("global".to_string())
                } else {
                    Some("local".to_string())
                };
                
                // Create the symbol
                let symbol = Symbol::new_with_details(
                    name.to_string(),
                    address,
                    None,  // Size not directly available
                    symbol_type,
                    None,  // Source file
                    None,  // Line number
                    visibility,
                    section_name,
                    binding,
                );
                
                // Add the symbol
                self.add_symbol(symbol);
            }
        }
        
        // Load dynamic symbols (from export trie if available)
        self.loading_progress = Some(0.7);
        self.loading_status = "Loading Mach-O dynamic symbols...".to_string();
        
        // We'll skip exports for now, as they're not directly accessible in the current goblin API
        // We'll have to come back to this later
        
        // Build indices after loading all symbols
        self.loading_progress = Some(0.9);
        self.loading_status = "Building indices...".to_string();
        self.build_indices();
        
        self.loading_progress = Some(1.0);
        self.loading_status = format!("Loaded {} Mach-O symbols", self.by_address.len());
        
        Ok(())
    }
    
    /// Load symbols from an ELF binary
    fn load_elf_symbols(&mut self, elf: &goblin::elf::Elf) -> Result<()> {
        self.loading_progress = Some(0.2);
        self.loading_status = "Loading ELF symbols...".to_string();
        
        // Load sections first
        self.loading_progress = Some(0.3);
        self.loading_status = "Loading ELF sections...".to_string();
        
        for section in &elf.section_headers {
            if let Some(name) = elf.shdr_strtab.get_at(section.sh_name) {
                // Skip sections with empty names
                if name.is_empty() {
                    continue;
                }
                
                let address = section.sh_addr;
                let size = section.sh_size;
                let flags = section.sh_flags;
                
                // Add to our section list
                self.sections.push(Section::new(
                    name.to_string(),
                    address,
                    size,
                    flags
                ));
                
                debug!("Added section: {} at 0x{:x} ({} bytes)", name, address, size);
            }
        }
        
        // Load symbols from symbol tables
        self.loading_progress = Some(0.4);
        self.loading_status = "Loading ELF symbols...".to_string();
        
        // Process a symbol from either the static or dynamic symbol table
        let process_symbol = |sym: &goblin::elf::Sym, strtab: &goblin::strtab::Strtab, is_dynamic: bool| {
            if let Some(name) = strtab.get_at(sym.st_name) {
                // Skip empty names or special indices
                if name.is_empty() || sym.st_shndx == 0 {
                    return;
                }
                
                let address = sym.st_value;
                let size = if sym.st_size > 0 { Some(sym.st_size) } else { None };
                
                // Determine symbol type
                let symbol_type = match goblin::elf::sym::st_type(sym.st_info) {
                    goblin::elf::sym::STT_FUNC => SymbolType::Function,
                    goblin::elf::sym::STT_OBJECT => SymbolType::GlobalVariable,
                    goblin::elf::sym::STT_SECTION => SymbolType::Other, // Skip section symbols
                    goblin::elf::sym::STT_FILE => SymbolType::Other,    // Skip file symbols
                    _ => {
                        // Check the section for additional context
                        let section_idx = sym.st_shndx as usize;
                        if section_idx < self.sections.len() {
                            let section = &self.sections[section_idx];
                            if section.is_executable {
                                SymbolType::Function
                            } else {
                                SymbolType::Data
                            }
                        } else {
                            SymbolType::Other
                        }
                    }
                };
                
                // Skip section and file symbols
                if symbol_type == SymbolType::Other && 
                   (goblin::elf::sym::st_type(sym.st_info) == goblin::elf::sym::STT_SECTION ||
                    goblin::elf::sym::st_type(sym.st_info) == goblin::elf::sym::STT_FILE) {
                    return;
                }
                
                // Determine visibility
                let bind = goblin::elf::sym::st_bind(sym.st_info);
                let visibility = match bind {
                    goblin::elf::sym::STB_GLOBAL => Some("global".to_string()),
                    goblin::elf::sym::STB_LOCAL => Some("local".to_string()),
                    goblin::elf::sym::STB_WEAK => Some("weak".to_string()),
                    _ => None,
                };
                
                // Get section name
                let section_idx = sym.st_shndx as usize;
                let section_name = if section_idx < self.sections.len() {
                    Some(self.sections[section_idx].name.clone())
                } else {
                    None
                };
                
                // Determine binding for consistency with Mach-O
                let binding = match bind {
                    goblin::elf::sym::STB_GLOBAL => Some("global".to_string()),
                    goblin::elf::sym::STB_LOCAL => Some("local".to_string()),
                    goblin::elf::sym::STB_WEAK => Some("weak".to_string()),
                    _ => None,
                };
                
                // Create the symbol
                let symbol = Symbol::new_with_details(
                    name.to_string(),
                    address,
                    size,
                    symbol_type,
                    None,  // Source file
                    None,  // Line number
                    visibility,
                    section_name,
                    binding,
                );
                
                // Add the symbol
                self.add_symbol(symbol);
            }
        };
        
        // Process regular symbols
        let symbol_count = elf.syms.len();
        for (i, sym) in elf.syms.iter().enumerate() {
            // Update progress every 100 symbols
            if i % 100 == 0 || i == symbol_count - 1 {
                let progress = 0.4 + 0.2 * (i as f32 / symbol_count as f32);
                self.loading_progress = Some(progress);
                self.loading_status = format!("Loading ELF symbols... {}/{}", i + 1, symbol_count);
            }
            
            process_symbol(&sym, &elf.strtab, false);
        }
        
        // Process dynamic symbols
        self.loading_progress = Some(0.6);
        self.loading_status = "Loading ELF dynamic symbols...".to_string();
        
        let dynsym_count = elf.dynsyms.len();
        for (i, sym) in elf.dynsyms.iter().enumerate() {
            // Update progress every 100 symbols
            if i % 100 == 0 || i == dynsym_count - 1 {
                let progress = 0.6 + 0.2 * (i as f32 / dynsym_count as f32);
                self.loading_progress = Some(progress);
                self.loading_status = format!("Loading ELF dynamic symbols... {}/{}", i + 1, dynsym_count);
            }
            
            process_symbol(&sym, &elf.dynstrtab, true);
        }
        
        // Build indices after loading all symbols
        self.loading_progress = Some(0.9);
        self.loading_status = "Building indices...".to_string();
        self.build_indices();
        
        self.loading_progress = Some(1.0);
        self.loading_status = format!("Loaded {} ELF symbols", self.by_address.len());
        
        Ok(())
    }
    
    /// Add a symbol to the table
    fn add_symbol(&mut self, symbol: Symbol) {
        let address = symbol.address();
        let name = symbol.name().to_string();
        let symbol_type = symbol.symbol_type();
        
        // Update symbol count by type
        *self.symbol_counts.entry(symbol_type).or_insert(0) += 1;
        
        // Add to address index
        self.by_address.insert(address, symbol.clone());
        
        // Add to name index
        self.by_name.insert(name.clone(), address);
        
        // Add to demangled name index if available
        if let Some(demangled) = symbol.demangled_name.as_ref() {
            self.by_demangled_name.insert(demangled.clone(), address);
            
            // Also add name prefixes for demangled name
            self.add_name_prefixes(demangled, address);
        }
        
        // Add name prefixes for raw name
        self.add_name_prefixes(&name, address);
        
        // Add to address range index
        if let Some(size) = symbol.size() {
            let end_address = address + size;
            self.address_ranges.push((address, end_address, address));
        }
    }
    
    /// Add name prefixes for autocompletion
    fn add_name_prefixes(&mut self, name: &str, address: u64) {
        // We'll add prefixes of length 3 or more for efficiency
        if name.len() < 3 {
            return;
        }
        
        // Add prefixes (min length 3) to the prefix index
        for len in 3..=name.len() {
            let prefix = name[..len].to_string();
            self.name_prefix_index
                .entry(prefix)
                .or_insert_with(Vec::new)
                .push(address);
        }
    }
    
    /// Find a symbol by address
    pub fn find_by_address(&self, address: u64) -> Option<&Symbol> {
        self.by_address.get(&address)
    }
    
    /// Find a symbol by address range
    pub fn find_by_address_range(&self, address: u64) -> Option<&Symbol> {
        // First, try to find an exact match (fastest)
        if let Some(symbol) = self.find_by_address(address) {
            return Some(symbol);
        }
        
        // Check our address range index using binary search
        if !self.address_ranges.is_empty() {
            // Binary search would be ideal, but tricky with overlapping ranges.
            // For simplicity, we'll use a linear search in our pre-built range list.
            for &(start, end, sym_addr) in &self.address_ranges {
                if address >= start && address < end {
                    return self.by_address.get(&sym_addr);
                }
            }
        }
        
        // As a fallback, check for containing section and find closest symbol
        if let Some(section) = self.find_section_by_address(address) {
            // Get all symbols in this section
            let section_symbols: Vec<(&u64, &Symbol)> = self.by_address.iter()
                .filter(|(_, sym)| sym.section.as_ref().map_or(false, |s| s == &section.name))
                .collect();
            
            if !section_symbols.is_empty() {
                // Find the closest symbol before the address
                let mut closest_sym = None;
                let mut closest_distance = u64::MAX;
                
                for (&sym_addr, sym) in &section_symbols {
                    if sym_addr <= address {
                        let distance = address - sym_addr;
                        if distance < closest_distance {
                            closest_distance = distance;
                            closest_sym = Some(*sym);
                        }
                    }
                }
                
                return closest_sym;
            }
        }
        
        None
    }
    
    /// Find a symbol by name (raw name)
    pub fn find_by_name(&self, name: &str) -> Option<&Symbol> {
        self.by_name.get(name).and_then(|addr| self.by_address.get(addr))
    }
    
    /// Find a symbol by demangled name
    pub fn find_by_demangled_name(&self, name: &str) -> Option<&Symbol> {
        self.by_demangled_name.get(name).and_then(|addr| self.by_address.get(addr))
    }
    
    /// Find a symbol by either raw or demangled name
    pub fn find_by_any_name(&self, name: &str) -> Option<&Symbol> {
        self.find_by_name(name)
            .or_else(|| self.find_by_demangled_name(name))
    }
    
    /// Get all symbols
    pub fn get_all_symbols(&self) -> Vec<&Symbol> {
        self.by_address.values().collect()
    }
    
    /// Get all functions
    pub fn get_all_functions(&self) -> Vec<&Symbol> {
        self.by_address.values()
            .filter(|sym| sym.is_function())
            .collect()
    }
    
    /// Get loading progress
    pub fn loading_progress(&self) -> Option<f32> {
        self.loading_progress
    }
    
    /// Get loading status
    pub fn loading_status(&self) -> &str {
        &self.loading_status
    }
    
    /// Get target architecture
    pub fn architecture(&self) -> Option<&str> {
        self.architecture.as_deref()
    }
    
    /// Get binary format
    pub fn binary_format(&self) -> Option<&str> {
        self.binary_format.as_deref()
    }
    
    /// Find symbols by name prefix (for autocompletion)
    pub fn find_by_prefix(&self, prefix: &str) -> Vec<&Symbol> {
        if prefix.len() < 3 {
            // For short prefixes, scan the entire list for efficiency
            return self.by_name.iter()
                .filter(|(name, _)| name.starts_with(prefix))
                .filter_map(|(_, &addr)| self.by_address.get(&addr))
                .collect();
        }
        
        // Use the prefix index for longer prefixes
        if let Some(addresses) = self.name_prefix_index.get(prefix) {
            return addresses.iter()
                .filter_map(|&addr| self.by_address.get(&addr))
                .collect();
        }
        
        // Try to find the longest matching prefix
        let mut matching_prefix = prefix[..3].to_string();
        for len in 4..=prefix.len() {
            let candidate = &prefix[..len];
            if self.name_prefix_index.contains_key(candidate) {
                matching_prefix = candidate.to_string();
            } else {
                break;
            }
        }
        
        // If we found a partial match, filter the results
        if let Some(addresses) = self.name_prefix_index.get(&matching_prefix) {
            return addresses.iter()
                .filter_map(|&addr| self.by_address.get(&addr))
                .filter(|sym| sym.name().starts_with(prefix) || 
                               sym.demangled_name.as_ref().map_or(false, |n| n.starts_with(prefix)))
                .collect();
        }
        
        Vec::new()
    }
    
    /// Find a symbol that contains the given address within its range
    pub fn find_containing_symbol(&self, address: u64) -> Option<&Symbol> {
        // First, try the exact address lookup for speed
        if let Some(symbol) = self.find_by_address(address) {
            return Some(symbol);
        }
        
        // Next, check the address ranges
        for &(start, end, symbol_addr) in &self.address_ranges {
            if address >= start && address < end {
                return self.by_address.get(&symbol_addr);
            }
        }
        
        // Finally, do a linear search through all symbols with size
        for (sym_addr, symbol) in &self.by_address {
            if let Some(size) = symbol.size() {
                let end_addr = *sym_addr + size;
                if address >= *sym_addr && address < end_addr {
                    return Some(symbol);
                }
            }
        }
        
        None
    }
    
    /// Get all symbols of a specific type
    pub fn get_symbols_by_type(&self, symbol_type: SymbolType) -> Vec<&Symbol> {
        self.by_address.values()
            .filter(|sym| sym.symbol_type() == symbol_type)
            .collect()
    }
    
    /// Get a section by address
    pub fn find_section_by_address(&self, address: u64) -> Option<&Section> {
        self.sections.iter()
            .find(|section| section.contains(address))
    }
    
    /// Get all sections
    pub fn get_all_sections(&self) -> &[Section] {
        &self.sections
    }
    
    /// Get executable sections
    pub fn get_executable_sections(&self) -> Vec<&Section> {
        self.sections.iter()
            .filter(|section| section.is_executable)
            .collect()
    }
    
    /// Get statistics about the symbol table
    pub fn get_statistics(&self) -> HashMap<String, usize> {
        let mut stats = HashMap::new();
        
        // Overall count
        stats.insert("total".to_string(), self.by_address.len());
        
        // Count by type
        for (symbol_type, count) in &self.symbol_counts {
            stats.insert(symbol_type.as_str().to_string(), *count);
        }
        
        // Sections count
        stats.insert("sections".to_string(), self.sections.len());
        
        stats
    }
    
    /// Build indices for fast lookups
    fn build_indices(&mut self) {
        // Clear existing indices
        self.address_ranges.clear();
        self.name_prefix_index.clear();
        
        // Rebuild address ranges
        let address_ranges: Vec<(u64, u64, u64)> = self.by_address.iter()
            .filter_map(|(&addr, symbol)| {
                symbol.size().map(|size| (addr, addr + size, addr))
            })
            .collect();
        
        // Add all the collected ranges to our index
        self.address_ranges.extend(address_ranges);
        
        // Create temporary collections for name prefixes
        let mut name_prefixes: Vec<(String, u64)> = Vec::new();
        
        // Collect name prefixes from raw names
        for (name, &addr) in &self.by_name {
            // Add prefixes of length 3 or more for efficiency
            if name.len() >= 3 {
                for len in 3..=name.len() {
                    let prefix = name[..len].to_string();
                    name_prefixes.push((prefix, addr));
                }
            }
        }
        
        // Collect name prefixes from demangled names
        for (name, &addr) in &self.by_demangled_name {
            // Add prefixes of length 3 or more for efficiency
            if name.len() >= 3 {
                for len in 3..=name.len() {
                    let prefix = name[..len].to_string();
                    name_prefixes.push((prefix, addr));
                }
            }
        }
        
        // Now add all collected prefixes to our index
        for (prefix, addr) in name_prefixes {
            self.name_prefix_index
                .entry(prefix)
                .or_insert_with(Vec::new)
                .push(addr);
        }
        
        // Sort address ranges for binary search
        self.address_ranges.sort_unstable_by_key(|&(start, _, _)| start);
        
        debug!("Built indices: {} address ranges, {} name prefixes", 
            self.address_ranges.len(), self.name_prefix_index.len());
    }
}

impl Default for SymbolTable {
    fn default() -> Self {
        Self::new()
    }
}

