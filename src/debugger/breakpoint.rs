/// Represents a breakpoint in the target program
#[derive(Clone, Debug)]
pub struct Breakpoint {
    /// Memory address of the breakpoint
    address: u64,
    /// Original data at the breakpoint location
    saved_data: u8,
    /// Is the breakpoint enabled?
    enabled: bool,
}

impl Breakpoint {
    /// Create a new breakpoint
    pub fn new(address: u64, saved_data: u8) -> Self {
        Self {
            address,
            saved_data,
            enabled: true,
        }
    }
    
    /// Get the address of the breakpoint
    pub fn address(&self) -> u64 {
        self.address
    }
    
    /// Get the original data at the breakpoint location
    pub fn saved_data(&self) -> u8 {
        self.saved_data
    }
    
    /// Check if the breakpoint is enabled
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }
    
    /// Enable the breakpoint
    pub fn enable(&mut self) {
        self.enabled = true;
    }
    
    /// Disable the breakpoint
    pub fn disable(&mut self) {
        self.enabled = false;
    }
}
