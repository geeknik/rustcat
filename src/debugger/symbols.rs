use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{anyhow, Result};
use goblin::Object;
use log::{debug, info};

/// Represents a symbol in the binary
#[derive(Debug, Clone)]
pub struct Symbol {
    /// Symbol name
    name: String,
    /// Memory address
    address: u64,
    /// Symbol size (if known)
    size: Option<u64>,
    /// Is the symbol a function?
    is_function: bool,
    /// Source file (if known)
    source_file: Option<String>,
    /// Line number (if known)
    line: Option<u32>,
}

impl Symbol {
    /// Create a new symbol
    pub fn new(
        name: String,
        address: u64,
        size: Option<u64>,
        is_function: bool,
        source_file: Option<String>,
        line: Option<u32>,
    ) -> Self {
        Self {
            name,
            address,
            size,
            is_function,
            source_file,
            line,
        }
    }
    
    /// Get the symbol name
    pub fn name(&self) -> &str {
        &self.name
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
        self.is_function
    }
    
    /// Get the source file
    pub fn source_file(&self) -> Option<&str> {
        self.source_file.as_deref()
    }
    
    /// Get the line number
    pub fn line(&self) -> Option<u32> {
        self.line
    }
}

/// Symbol table for the target program
pub struct SymbolTable {
    /// Symbols by address
    by_address: BTreeMap<u64, Symbol>,
    /// Symbols by name
    by_name: BTreeMap<String, u64>,
    /// Loading progress
    loading_progress: Option<f32>,
    /// Loading status
    loading_status: String,
}

impl SymbolTable {
    /// Create a new empty symbol table
    pub fn new() -> Self {
        Self {
            by_address: BTreeMap::new(),
            by_name: BTreeMap::new(),
            loading_progress: None,
            loading_status: "Not loaded".to_string(),
        }
    }
    
    /// Load symbols from a file
    pub fn load_from_file<P: AsRef<Path>>(&mut self, path: P) -> Result<()> {
        // Clear existing symbols
        self.by_address.clear();
        self.by_name.clear();
        
        self.loading_progress = Some(0.0);
        self.loading_status = "Loading file...".to_string();
        
        // Read the file
        let data = std::fs::read(path)?;
        
        self.loading_progress = Some(0.1);
        self.loading_status = "Parsing binary...".to_string();
        
        // Parse the binary
        let binary = Object::parse(&data)?;
        match binary {
            Object::Mach(mach_o) => {
                // We need to handle both fat and non-fat Mach-O binaries
                match mach_o {
                    goblin::mach::Mach::Binary(macho) => {
                        self.load_macho_symbols(&macho)?;
                    },
                    goblin::mach::Mach::Fat(fat) => {
                        // For fat binaries, find the ARM64 slice
                        for i in 0..fat.narches {
                            // Use direct get method to retrieve slice
                            if let Ok(slice) = fat.get(i) {
                                // Extract the MachO binary from the slice
                                match slice {
                                    goblin::mach::SingleArch::MachO(macho) => {
                                        // CPU_TYPE_ARM64 == 0x100000C
                                        if macho.header.cputype == 0x100000C {
                                            self.load_macho_symbols(&macho)?;
                                            break;
                                        }
                                    },
                                    _ => continue,
                                }
                            }
                        }
                    }
                }
            },
            Object::Elf(elf) => {
                self.load_elf_symbols(&elf)?;
            },
            _ => return Err(anyhow!("Unsupported binary format")),
        };
        
        self.loading_progress = Some(1.0);
        self.loading_status = format!("Loaded {} symbols", self.by_address.len());
        
        Ok(())
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
                        // Check if this is a function symbol using the n_type field
                        // This would be more accurate in a real implementation
                        let is_function = true; // Simplified for now
                        
                        let symbol = Symbol::new(
                            name.to_string(),
                            addr_value,
                            None, // Size not available from mach-o symbols
                            is_function,
                            None, // Source file info would require DWARF parsing
                            None, // Line info would require DWARF parsing
                        );
                        
                        self.add_symbol(symbol);
                    }
                }
                
                if i % 1000 == 0 {
                    self.loading_progress = Some(0.2 + 0.7 * (i as f32 / total as f32));
                    self.loading_status = format!("Loaded {}/{} symbols", i, total);
                }
            }
        }
        
        // Load code sections and function starts
        // Handle the Result from segment.name() properly
        for segment in macho.segments.iter() {
            if let Ok(name) = segment.name() {
                if name.starts_with("__TEXT") {
                    if let Ok(sections) = segment.sections() {
                        for section in sections.iter() {
                            let (section_name, _section_data) = section;
                            // Convert section name bytes to string for comparison
                            if std::str::from_utf8(&section_name.sectname)
                                .map(|s| s.contains("__text") || s.contains("__stubs"))
                                .unwrap_or(false)
                            {
                                // This could be a text section with code
                                // In a real implementation, we'd extract function starts from here
                                // For now, we'll just log that we found it
                                debug!("Found code section: {:?}", section_name);
                            }
                        }
                    }
                }
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
                let name = match elf.strtab.get_at(sym.st_name) {
                    Some(name) => name.to_string(),
                    None => format!("UNKNOWN_{:x}", sym.st_value),
                };
                
                let symbol = Symbol::new(
                    name,
                    sym.st_value,
                    Some(sym.st_size),
                    sym.is_function(),
                    None,
                    None,
                );
                
                self.add_symbol(symbol);
            }
            
            if i % 1000 == 0 {
                self.loading_progress = Some(0.2 + 0.7 * (i as f32 / total as f32));
                self.loading_status = format!("Loaded {}/{} symbols", i, total);
            }
        }
        
        // Also load dynamic symbols
        for (i, sym) in elf.dynsyms.iter().enumerate() {
            if sym.st_value > 0 {
                let name = match elf.dynstrtab.get_at(sym.st_name) {
                    Some(name) => name.to_string(),
                    None => format!("DYN_UNKNOWN_{:x}", sym.st_value),
                };
                
                let symbol = Symbol::new(
                    name,
                    sym.st_value,
                    Some(sym.st_size),
                    sym.is_function(),
                    None,
                    None,
                );
                
                // Only add if we don't already have this address
                if !self.by_address.contains_key(&sym.st_value) {
                    self.add_symbol(symbol);
                }
            }
        }
        
        Ok(())
    }
    
    /// Add a symbol to the table
    fn add_symbol(&mut self, symbol: Symbol) {
        let addr = symbol.address();
        let name = symbol.name().to_string();
        
        self.by_address.insert(addr, symbol);
        self.by_name.insert(name, addr);
    }
    
    /// Find a symbol by address
    pub fn find_by_address(&self, address: u64) -> Option<&Symbol> {
        // Find the closest symbol that is <= the given address
        self.by_address
            .range(..=address)
            .next_back()
            .map(|(_, symbol)| symbol)
    }
    
    /// Find a symbol by name
    pub fn find_by_name(&self, name: &str) -> Option<&Symbol> {
        self.by_name
            .get(name)
            .and_then(|&addr| self.by_address.get(&addr))
    }
    
    /// Get all symbols
    pub fn get_all_symbols(&self) -> Vec<&Symbol> {
        self.by_address.values().collect()
    }
    
    /// Get the loading progress
    pub fn loading_progress(&self) -> Option<f32> {
        self.loading_progress
    }
    
    /// Get the loading status
    pub fn loading_status(&self) -> &str {
        &self.loading_status
    }
}

impl Default for SymbolTable {
    fn default() -> Self {
        Self::new()
    }
}
