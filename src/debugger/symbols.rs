use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{anyhow, Result};
use goblin::Object;
use log::{debug, warn};
use cpp_demangle::Symbol as CppSymbol;

/// Symbol type classification
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
        // Try to demangle C++ symbol names
        let demangled_name = if name.starts_with("_Z") || name.starts_with("__Z") {
            // This looks like a mangled C++ name, try to demangle it
            let mangled_part = if name.starts_with("__Z") { &name[1..] } else { &name };
            match CppSymbol::new(mangled_part) {
                Ok(demangled) => Some(demangled.to_string()),
                Err(_) => None,
            }
        } else {
            None
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
        }
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
}

/// Symbol table for the target program
pub struct SymbolTable {
    /// Symbols by address
    by_address: BTreeMap<u64, Symbol>,
    /// Symbols by name
    by_name: BTreeMap<String, u64>,
    /// Demangled names to address mapping
    by_demangled_name: BTreeMap<String, u64>,
    /// Loading progress
    loading_progress: Option<f32>,
    /// Loading status
    loading_status: String,
    /// Target architecture
    architecture: Option<String>,
    /// Binary format
    binary_format: Option<String>,
}

impl SymbolTable {
    /// Create a new empty symbol table
    pub fn new() -> Self {
        Self {
            by_address: BTreeMap::new(),
            by_name: BTreeMap::new(),
            by_demangled_name: BTreeMap::new(),
            loading_progress: None,
            loading_status: "Not loaded".to_string(),
            architecture: None,
            binary_format: None,
        }
    }
    
    /// Load symbols from a file
    pub fn load_from_file<P: AsRef<Path>>(&mut self, path: P) -> Result<()> {
        // Clear existing symbols
        self.by_address.clear();
        self.by_name.clear();
        self.by_demangled_name.clear();
        
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
        
        // Load symbols from symbol table
        if let Some(symbols) = &macho.symbols {
            let total = symbols.iter().count();
            for (i, symbol_result) in symbols.iter().enumerate() {
                if let Ok((name, nlist)) = symbol_result {
                    let addr_value = nlist.n_value;
                    if addr_value > 0 {
                        // Determine symbol type based on nlist n_type and n_sect fields
                        let symbol_type = if (nlist.n_type & 0x0e) == 0x0e {
                            // N_SECT | N_EXT | N_PEXT (defined in section, global visibility)
                            if nlist.n_sect == 1 {
                                // __TEXT section usually contains functions
                                SymbolType::Function 
                            } else {
                                // Other sections usually contain data
                                SymbolType::GlobalVariable
                            }
                        } else if (nlist.n_type & 0x0e) == 0x06 {
                            // N_SECT (defined in section, static visibility)
                            if nlist.n_sect == 1 {
                                SymbolType::Function
                            } else {
                                SymbolType::StaticVariable
                            }
                        } else {
                            SymbolType::Other
                        };
                        
                        // Determine visibility
                        let visibility = if (nlist.n_type & 0x01) != 0 {
                            // N_EXT bit set means global/external
                            Some("global".to_string())
                        } else {
                            Some("local".to_string())
                        };
                        
                        let symbol = Symbol::new(
                            name.to_string(),
                            addr_value,
                            None, // Size not available from mach-o symbols
                            symbol_type,
                            None, // Source file info would require DWARF parsing
                            None, // Line info would require DWARF parsing
                            visibility,
                        );
                        
                        self.add_symbol(symbol);
                    }
                }
                
                if i % 1000 == 0 {
                    self.loading_progress = Some(0.7f32.mul_add(i as f32 / total as f32, 0.2));
                    self.loading_status = format!("Loaded {}/{} symbols", i, total);
                }
            }
        }
        
        // Load code sections and function starts
        // Handle the Result from segment.name() properly
        for segment in &macho.segments {
            if let Ok(name) = segment.name() {
                if name.starts_with("__TEXT") {
                    // Using simplified section handling compatible with goblin 0.7.1
                    debug!("Found __TEXT segment at 0x{:x}", segment.vmaddr);
                    
                    // In a production debugger, we'd examine the sections more carefully
                    // but for now, we'll focus on getting symbols working
                }
            }
        }
        
        // Try to parse function starts if available
        // Note: goblin 0.7.1 doesn't expose function_starts directly
        // We'll handle this differently by detecting functions from symbols
        let text_base = macho.segments
            .iter().find_map(|s| s.name().ok().filter(|n| n.starts_with("__TEXT")).map(|_| s.vmaddr))
            .unwrap_or(0);
            
        // Function detection is now primarily done through the symbol table
        let mut function_starts = Vec::new();
        
        // Extract potential function start addresses from symbols
        if let Some(symbols) = &macho.symbols {
            for (_, sym) in symbols.iter().flatten() {
                // Check if it's a function symbol (in __TEXT section)
                if (sym.n_type & 0x0e) == 0x0e && sym.n_sect == 1 && sym.n_value > 0 {
                    let offset = sym.n_value - text_base;
                    function_starts.push(offset);
                }
            }
        }
            
        for (i, start) in function_starts.iter().enumerate() {
            let addr = text_base + start;
            
            // Only add unnamed functions if they aren't already in our symbol table
            if !self.by_address.contains_key(&addr) {
                let symbol = Symbol::new(
                    format!("sub_{:x}", addr),
                    addr,
                    None,
                    SymbolType::Function,
                    None,
                    None,
                    Some("local".to_string()),
                );
                
                self.add_symbol(symbol);
            }
            
            if i % 1000 == 0 && !function_starts.is_empty() {
                self.loading_progress = Some(0.1f32.mul_add(i as f32 / function_starts.len() as f32, 0.9));
                self.loading_status = format!("Processing function starts {}/{}", i, function_starts.len());
            }
        }
        
        Ok(())
    }
    
    /// Load symbols from an ELF binary
    fn load_elf_symbols(&mut self, elf: &goblin::elf::Elf) -> Result<()> {
        self.loading_progress = Some(0.2);
        self.loading_status = "Loading ELF symbols...".to_string();
        
        // Load symbols from symbol table
        let total = elf.syms.len();
        for (i, sym) in elf.syms.iter().enumerate() {
            if sym.st_value > 0 {
                // Skip empty symbols
                if let Some(name) = elf.strtab.get_at(sym.st_name) {
                    if !name.is_empty() {
                        // Determine symbol type
                        let symbol_type = match sym.st_type() {
                            goblin::elf::sym::STT_FUNC => SymbolType::Function,
                            goblin::elf::sym::STT_OBJECT => {
                                if (sym.st_info >> 4) == goblin::elf::sym::STB_GLOBAL {
                                    SymbolType::GlobalVariable
                                } else {
                                    SymbolType::StaticVariable
                                }
                            },
                            goblin::elf::sym::STT_SECTION => SymbolType::Text, // Could be data too
                            _ => SymbolType::Other,
                        };
                        
                        // Determine visibility
                        let bind = sym.st_info >> 4;
                        let visibility = if bind == goblin::elf::sym::STB_GLOBAL {
                            Some("global".to_string())
                        } else if bind == goblin::elf::sym::STB_LOCAL {
                            Some("local".to_string())
                        } else if bind == goblin::elf::sym::STB_WEAK {
                            Some("weak".to_string()) 
                        } else {
                            None
                        };
                        
                        let symbol = Symbol::new(
                            name.to_string(),
                            sym.st_value,
                            Some(sym.st_size),
                            symbol_type,
                            None, // Source file info would require DWARF parsing
                            None, // Line info would require DWARF parsing
                            visibility,
                        );
                        
                        self.add_symbol(symbol);
                    }
                }
            }
            
            if i % 1000 == 0 {
                self.loading_progress = Some(0.7f32.mul_add(i as f32 / total as f32, 0.2));
                self.loading_status = format!("Loaded {}/{} symbols", i, total);
            }
        }
        
        // Also load dynamic symbols
        let total_dynsyms = elf.dynsyms.len();
        for (i, sym) in elf.dynsyms.iter().enumerate() {
            if sym.st_value > 0 {
                // Skip empty symbols
                if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
                    if !name.is_empty() && !self.by_name.contains_key(name) {
                        // Determine symbol type
                        let symbol_type = match sym.st_type() {
                            goblin::elf::sym::STT_FUNC => SymbolType::Function,
                            goblin::elf::sym::STT_OBJECT => {
                                if (sym.st_info >> 4) == goblin::elf::sym::STB_GLOBAL {
                                    SymbolType::GlobalVariable
                                } else {
                                    SymbolType::StaticVariable
                                }
                            },
                            _ => SymbolType::Other,
                        };
                        
                        // Determine visibility
                        let bind = sym.st_info >> 4;
                        let visibility = if bind == goblin::elf::sym::STB_GLOBAL {
                            Some("global".to_string())
                        } else if bind == goblin::elf::sym::STB_LOCAL {
                            Some("local".to_string())
                        } else if bind == goblin::elf::sym::STB_WEAK {
                            Some("weak".to_string()) 
                        } else {
                            None
                        };
                        
                        let symbol = Symbol::new(
                            name.to_string(),
                            sym.st_value,
                            Some(sym.st_size),
                            symbol_type,
                            None,
                            None,
                            visibility,
                        );
                        
                        self.add_symbol(symbol);
                    }
                }
            }
            
            if i % 1000 == 0 {
                self.loading_progress = Some(0.1f32.mul_add(i as f32 / total_dynsyms as f32, 0.9));
                self.loading_status = format!("Loaded {}/{} dynamic symbols", i, total_dynsyms);
            }
        }
        
        Ok(())
    }
    
    /// Add a symbol to the symbol table
    fn add_symbol(&mut self, symbol: Symbol) {
        let addr = symbol.address();
        let name = symbol.name().to_string();
        
        // Add to address map
        self.by_address.insert(addr, symbol.clone());
        
        // Add to name map (only if not already present or if this is a better symbol)
        self.by_name.entry(name).or_insert(addr);
        
        // Add to demangled name map if available
        if let Some(demangled) = &symbol.demangled_name {
            self.by_demangled_name.entry(demangled.clone()).or_insert(addr);
        }
    }
    
    /// Find a symbol by address
    pub fn find_by_address(&self, address: u64) -> Option<&Symbol> {
        self.by_address.get(&address)
    }
    
    /// Find a symbol by address range (within the symbol's range if size is known)
    pub fn find_by_address_range(&self, address: u64) -> Option<&Symbol> {
        // First try exact match
        if let Some(symbol) = self.by_address.get(&address) {
            return Some(symbol);
        }
        
        // Try range-based lookup
        for symbol in self.by_address.values() {
            if let Some(size) = symbol.size {
                if address >= symbol.address && address < symbol.address + size {
                    return Some(symbol);
                }
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
}

impl Default for SymbolTable {
    fn default() -> Self {
        Self::new()
    }
}
