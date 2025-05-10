use std::collections::HashMap;

/// Represents a region of memory in the target process
pub struct MemoryRegion {
    /// Start address of the region
    start: u64,
    /// End address of the region
    end: u64,
    /// Permissions of the region (r, w, x)
    permissions: u8,
    /// Name of the region (if available)
    name: Option<String>,
}

impl MemoryRegion {
    /// Create a new memory region
    pub fn new(start: u64, end: u64, permissions: u8, name: Option<String>) -> Self {
        Self {
            start,
            end,
            permissions,
            name,
        }
    }
    
    /// Check if an address is within this region
    pub fn contains(&self, address: u64) -> bool {
        address >= self.start && address < self.end
    }
    
    /// Get the size of the region
    pub fn size(&self) -> u64 {
        self.end - self.start
    }
    
    /// Check if the region is readable
    pub fn is_readable(&self) -> bool {
        (self.permissions & 0x1) != 0
    }
    
    /// Check if the region is writable
    pub fn is_writable(&self) -> bool {
        (self.permissions & 0x2) != 0
    }
    
    /// Check if the region is executable
    pub fn is_executable(&self) -> bool {
        (self.permissions & 0x4) != 0
    }
}

/// Memory map of the target process
pub struct MemoryMap {
    /// Regions of memory in the target process
    regions: Vec<MemoryRegion>,
    /// Cache of recently accessed regions
    region_cache: HashMap<u64, usize>,
}

impl MemoryMap {
    /// Create a new memory map
    pub fn new() -> Self {
        Self {
            regions: Vec::new(),
            region_cache: HashMap::new(),
        }
    }
    
    /// Add a memory region to the map
    pub fn add_region(&mut self, region: MemoryRegion) {
        self.regions.push(region);
    }
    
    /// Find the region containing the specified address
    pub fn find_region(&mut self, address: u64) -> Option<&MemoryRegion> {
        // Check cache first
        if let Some(&index) = self.region_cache.get(&(address & !0xFFF)) {
            let region = &self.regions[index];
            if region.contains(address) {
                return Some(region);
            }
        }
        
        // Linear search through regions
        for (i, region) in self.regions.iter().enumerate() {
            if region.contains(address) {
                // Add to cache
                self.region_cache.insert(address & !0xFFF, i);
                return Some(region);
            }
        }
        
        None
    }
    
    /// Get all regions in the memory map
    pub fn get_regions(&self) -> &[MemoryRegion] {
        &self.regions
    }
    
    /// Clear the memory map
    pub fn clear(&mut self) {
        self.regions.clear();
        self.region_cache.clear();
    }
}
