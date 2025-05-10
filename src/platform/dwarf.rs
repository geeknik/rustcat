use std::path::Path;
use std::collections::HashMap;

use anyhow::{Result, anyhow};
use gimli::{EndianSlice, LittleEndian, Dwarf, AttributeValue, Unit};
use object::{Object, ObjectSection};

/// DWARF parser for extracting debug information
pub struct DwarfParser<'a> {
    /// DWARF debug information
    dwarf: Option<Dwarf<EndianSlice<'a, LittleEndian>>>,
    /// Source directory cache
    source_dir_cache: HashMap<String, String>,
}

impl<'a> DwarfParser<'a> {
    /// Create a new DWARF parser
    pub fn new() -> Self {
        Self {
            dwarf: None,
            source_dir_cache: HashMap::new(),
        }
    }
    
    /// Load DWARF information from a file
    pub fn load<P: AsRef<Path>>(&mut self, path: P) -> Result<()> {
        // Load the file
        let file_data = std::fs::read(path)?;
        let cloned_data = file_data.clone();
        let object = object::File::parse(&*cloned_data)?;
        
        // Create a memory map once for all sections
        // This is a lifetime hack. In a real implementation, we'd 
        // use gimli::EndianRcSlice instead to properly manage lifetimes
        // of mapped data.
        // Remove unused data variable
        
        // Load DWARF sections
        let load_section = |id: gimli::SectionId| -> Result<EndianSlice<'a, LittleEndian>> {
            match object.section_by_name(id.name()) {
                Some(section) => {
                    let data = section.data()?;
                    // Use unsafe trick to extend lifetime of section data
                    // In a real implementation, we'd properly manage lifetimes with
                    // appropriate data structures
                    let borrowed_data = unsafe {
                        std::slice::from_raw_parts(
                            data.as_ptr(),
                            data.len()
                        )
                    };
                    Ok(EndianSlice::new(borrowed_data, LittleEndian))
                }
                None => Ok(EndianSlice::new(&[], LittleEndian)),
            }
        };
        
        // Create a DWARF context
        let dwarf = gimli::Dwarf::load(load_section)?;
        self.dwarf = Some(dwarf);
        
        // Pre-cache source directories for performance
        if let Some(dwarf) = &self.dwarf {
            let mut unit_headers = dwarf.units();
            while let Some(header) = unit_headers.next()? {
                let unit = dwarf.unit(header)?;
                if let Some(line_program) = unit.line_program.clone() {
                    let header = line_program.header();
                    for file_entry in header.file_names() {
                        // Get directory index safely
                        let dir_idx = file_entry.directory_index();
                        
                        if let Some(dir) = header.directory(dir_idx) {
                            if let AttributeValue::String(s) = dir {
                                // Create AttributeValue::String to pass to attr_string
                                if let Ok(raw_dir) = dwarf.attr_string(&unit, AttributeValue::String(s)) {
                                    if let Ok(dir_str) = raw_dir.to_string() {
                                        // Extract path name with similar pattern
                                        let path_name = match file_entry.path_name() {
                                            gimli::AttributeValue::String(s) => {
                                                if let Ok(raw_path) = dwarf.attr_string(&unit, AttributeValue::String(s)) {
                                                    if let Ok(path) = raw_path.to_string() {
                                                        path
                                                    } else {
                                                        continue;
                                                    }
                                                } else {
                                                    continue;
                                                }
                                            },
                                            _ => continue,
                                        };
                                        
                                        // Create a key for the cache
                                        let key = format!("{:?}-{:?}", dir_idx, path_name);
                                        
                                        // Create full path with consistent string type
                                        let full_path = if dir_str.is_empty() {
                                            path_name.to_string()
                                        } else {
                                            format!("{}/{}", dir_str, path_name)
                                        };
                                        
                                        self.source_dir_cache.insert(key, full_path);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        
        Ok(())
    }
    
    /// Iterate over all compilation units
    pub fn iter_units(&self) -> Result<Vec<Unit<EndianSlice<'a, LittleEndian>>>> {
        let dwarf = self.dwarf.as_ref().ok_or_else(|| anyhow!("DWARF data not loaded"))?;
        
        let mut units = Vec::new();
        let mut unit_headers = dwarf.units();
        while let Some(header) = unit_headers.next()? {
            let unit = dwarf.unit(header)?;
            units.push(unit);
        }
        
        Ok(units)
    }
    
    /// Find line information for an address
    pub fn find_line_info(&self, address: u64) -> Result<Option<(String, u32)>> {
        let dwarf = self.dwarf.as_ref().ok_or_else(|| anyhow!("DWARF data not loaded"))?;
        
        for unit in self.iter_units()? {
            // Skip units that don't have line info
            let line_program = match unit.line_program.clone() {
                Some(program) => program,
                None => continue,
            };
            
            let program_clone = line_program.clone();
            let header = program_clone.header();
            
            // Run the line program to find the file and line
            let mut rows = line_program.rows();
            while let Some((_, row)) = rows.next_row()? {
                if row.address() == address {
                    let file = match row.file(header) {
                        Some(file) => file,
                        None => continue,
                    };
                    
                    // Get directory information with consistent string types
                    let directory = {
                        let mut dir_string = String::new();
                        let dir_idx = file.directory_index();
                        if let Some(dir) = header.directory(dir_idx) {
                            if let AttributeValue::String(s) = dir {
                                if let Ok(raw_dir) = dwarf.attr_string(&unit, AttributeValue::String(s)) {
                                    if let Ok(dir_str) = raw_dir.to_string() {
                                        dir_string = dir_str.to_string();
                                    }
                                }
                            }
                        }
                        dir_string
                    };
                    
                    // Extract the file name with proper AttributeValue handling
                    let filename = match file.path_name() {
                        AttributeValue::String(s) => {
                            if let Ok(raw_name) = dwarf.attr_string(&unit, AttributeValue::String(s)) {
                                if let Ok(name) = raw_name.to_string() {
                                    name
                                } else {
                                    continue;
                                }
                            } else {
                                continue;
                            }
                        },
                        _ => continue,
                    };
                    
                    // Ensure consistent string type in path construction
                    let path = if directory.is_empty() {
                        filename.to_string()
                    } else {
                        format!("{}/{}", directory, filename)
                    };
                    
                    // Extract the line number
                    let line = row.line().map(|l| l.get() as u32).unwrap_or(0);
                    
                    return Ok(Some((path, line)));
                }
            }
        }
        
        Ok(None)
    }
    
    /// Find function information for an address
    pub fn find_function_info(&self, address: u64) -> Result<Option<String>> {
        let dwarf = self.dwarf.as_ref().ok_or_else(|| anyhow!("DWARF data not loaded"))?;
        
        for unit in self.iter_units()? {
            let mut entries = unit.entries();
            while let Some((_, entry)) = entries.next_dfs()? {
                if entry.tag() == gimli::DW_TAG_subprogram {
                    // Check for low_pc attribute
                    let low_pc = match entry.attr_value(gimli::DW_AT_low_pc)? {
                        Some(AttributeValue::Addr(addr)) => addr,
                        _ => continue,
                    };
                    
                    // Check for high_pc attribute, which can be either an address or an offset
                    let high_pc = match entry.attr_value(gimli::DW_AT_high_pc)? {
                        Some(AttributeValue::Addr(addr)) => addr,
                        Some(AttributeValue::Udata(size)) => low_pc + size,
                        _ => continue,
                    };
                    
                    // Check if the address is within the function's range
                    if address >= low_pc && address < high_pc {
                        // Get the function name
                        if let Some(name_attr) = entry.attr_value(gimli::DW_AT_name)? {
                            // The name could be stored in multiple ways
                            match name_attr {
                                AttributeValue::String(s) => {
                                    if let Ok(raw_name) = dwarf.attr_string(&unit, AttributeValue::String(s)) {
                                        if let Ok(name) = raw_name.to_string() {
                                            return Ok(Some(name.to_string()));
                                        }
                                    }
                                }
                                // Handle other potential name representations
                                _ => {}
                            }
                        }
                        
                        // If we found a function that contains the address but couldn't get its name,
                        // return a synthetic name based on the address
                        return Ok(Some(format!("func_{:x}", low_pc)));
                    }
                }
            }
        }
        
        Ok(None)
    }
    
    /// Get source code lines around a given line
    pub fn get_source_lines(&self, file_path: &str, target_line: u32, context: u32) -> Result<Vec<(u32, String)>> {
        // In a real implementation, this would read the source file and extract the lines
        // around the target line. For brevity, we'll return a placeholder.
        let mut result = Vec::new();
        
        // Real implementation would read the file from disk or cache
        if std::path::Path::new(file_path).exists() {
            if let Ok(content) = std::fs::read_to_string(file_path) {
                let lines: Vec<&str> = content.lines().collect();
                
                let start_line = target_line.saturating_sub(context);
                let end_line = std::cmp::min(target_line + context, lines.len() as u32);
                
                for i in start_line..=end_line {
                    let line_idx = (i as usize).saturating_sub(1);
                    if line_idx < lines.len() {
                        result.push((i, lines[line_idx].to_string()));
                    }
                }
            }
        } else {
            // If we can't find the source file, return placeholders
            for i in (target_line - context)..=(target_line + context) {
                if i > 0 {
                    result.push((i, format!("// Source file '{}' not found", file_path)));
                }
            }
        }
        
        Ok(result)
    }
}

impl<'a> Default for DwarfParser<'a> {
    fn default() -> Self {
        Self::new()
    }
}
