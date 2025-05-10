use std::fmt;
use anyhow::Result;

/// Breakpoint type classification
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BreakpointType {
    /// Normal execution breakpoint
    Execution,
    /// Hardware breakpoint (using debug registers)
    #[allow(dead_code)]
    Hardware,
    /// Software watchpoint (memory read/write)
    #[allow(dead_code)]
    Watchpoint,
    /// One-shot breakpoint (auto-deletes after being hit)
    #[allow(dead_code)]
    OneShot,
    /// Conditional breakpoint
    #[allow(dead_code)]
    Conditional,
    /// Logging breakpoint (doesn't stop execution)
    #[allow(dead_code)]
    Logging,
}

impl BreakpointType {
    /// Convert to string representation
    pub fn as_str(&self) -> &'static str {
        match self {
            BreakpointType::Execution => "execution",
            BreakpointType::Hardware => "hardware",
            BreakpointType::Watchpoint => "watchpoint",
            BreakpointType::OneShot => "one-shot",
            BreakpointType::Conditional => "conditional",
            BreakpointType::Logging => "logging",
        }
    }
}

/// Represents a breakpoint in the target program
#[derive(Clone, Debug)]
pub struct Breakpoint {
    /// Memory address of the breakpoint
    address: u64,
    /// Original data at the breakpoint location
    saved_data: u8,
    /// Is the breakpoint enabled?
    enabled: bool,
    /// Breakpoint type
    breakpoint_type: BreakpointType,
    /// Hit count (how many times this breakpoint has been hit)
    hit_count: usize,
    /// Ignore count (how many hits to ignore before stopping)
    ignore_count: usize,
    /// Condition (expression to evaluate, breakpoint triggers only if true)
    condition: Option<String>,
    /// Log message for logging breakpoints
    #[allow(dead_code)]
    log_message: Option<String>,
    /// Symbol name associated with this breakpoint (if any)
    symbol_name: Option<String>,
    /// Source file and line information (if available)
    source_location: Option<(String, u32)>,
    /// User-provided breakpoint ID/name
    id: Option<String>,
}

impl Breakpoint {
    /// Create a new breakpoint
    pub fn new(address: u64, saved_data: u8) -> Self {
        Self {
            address,
            saved_data,
            enabled: true,
            breakpoint_type: BreakpointType::Execution,
            hit_count: 0,
            ignore_count: 0,
            condition: None,
            log_message: None,
            symbol_name: None,
            source_location: None,
            id: None,
        }
    }

    /// Create a new breakpoint with a specific type
    pub fn new_with_type(address: u64, saved_data: u8, breakpoint_type: BreakpointType) -> Self {
        Self {
            address,
            saved_data,
            enabled: true,
            breakpoint_type,
            hit_count: 0,
            ignore_count: 0,
            condition: None,
            log_message: None,
            symbol_name: None,
            source_location: None,
            id: None,
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
    
    /// Get the breakpoint type
    pub fn breakpoint_type(&self) -> BreakpointType {
        self.breakpoint_type
    }
    
    /// Set the breakpoint type
    pub fn set_breakpoint_type(&mut self, breakpoint_type: BreakpointType) {
        self.breakpoint_type = breakpoint_type;
    }
    
    /// Get the hit count
    pub fn hit_count(&self) -> usize {
        self.hit_count
    }
    
    /// Increment the hit count and check if we should break
    pub fn hit(&mut self) -> bool {
        self.hit_count += 1;
        
        // For one-shot breakpoints, disable after being hit
        if self.breakpoint_type == BreakpointType::OneShot {
            self.enabled = false;
        }
        
        // Check if we should ignore this hit
        if self.hit_count <= self.ignore_count {
            return false;
        }
        
        // For logging breakpoints, never actually stop
        if self.breakpoint_type == BreakpointType::Logging {
            return false;
        }
        
        // Otherwise, we should break (conditional evaluation happens separately)
        true
    }
    
    /// Reset the hit count
    pub fn reset_hit_count(&mut self) {
        self.hit_count = 0;
    }
    
    /// Set the ignore count
    pub fn set_ignore_count(&mut self, count: usize) {
        self.ignore_count = count;
    }
    
    /// Get the ignore count
    pub fn ignore_count(&self) -> usize {
        self.ignore_count
    }
    
    /// Set a condition for the breakpoint
    pub fn set_condition(&mut self, condition: Option<String>) {
        let has_condition = condition.is_some();
        self.condition = condition;
        
        if has_condition {
            self.breakpoint_type = BreakpointType::Conditional;
        } else if self.breakpoint_type == BreakpointType::Conditional {
            self.breakpoint_type = BreakpointType::Execution;
        }
    }
    
    /// Get the condition
    pub fn condition(&self) -> Option<&str> {
        self.condition.as_deref()
    }
    
    /// Set a log message for the breakpoint
    pub fn set_log_message(&mut self, message: Option<String>) {
        self.log_message = message;
    }
    
    /// Get the log message
    pub fn log_message(&self) -> Option<&str> {
        self.log_message.as_deref()
    }
    
    /// Set the symbol name associated with this breakpoint
    pub fn set_symbol_name(&mut self, name: Option<String>) {
        self.symbol_name = name;
    }
    
    /// Get the symbol name
    pub fn symbol_name(&self) -> Option<&str> {
        self.symbol_name.as_deref()
    }
    
    /// Set the source location
    pub fn set_source_location(&mut self, file: &str, line: u32) {
        self.source_location = Some((file.to_string(), line));
    }
    
    /// Get the source location
    pub fn source_location(&self) -> Option<(&str, u32)> {
        self.source_location.as_ref().map(|(file, line)| (file.as_str(), *line))
    }
    
    /// Set a unique ID for this breakpoint
    pub fn set_id(&mut self, id: Option<String>) {
        self.id = id;
    }
    
    /// Get the breakpoint ID
    pub fn id(&self) -> Option<&str> {
        self.id.as_deref()
    }
    
    /// Check if this breakpoint should trigger based on its condition
    pub fn evaluate_condition(&self, _debugger: &dyn ConditionEvaluator) -> Result<bool> {
        // If there's no condition, always trigger
        if self.condition.is_none() {
            return Ok(true);
        }
        
        // For now, we'll just pretend all conditions are true
        // In a real implementation, we'd evaluate the condition expression
        Ok(true)
    }
    
    /// Get a descriptive name for this breakpoint
    pub fn get_description(&self) -> String {
        if let Some(id) = &self.id {
            return id.clone();
        }
        
        if let Some(name) = &self.symbol_name {
            return name.clone();
        }
        
        if let Some((file, line)) = &self.source_location {
            return format!("{}:{}", file, line);
        }
        
        format!("0x{:x}", self.address)
    }
}

impl fmt::Display for Breakpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let status = if self.enabled { "enabled" } else { "disabled" };
        let bp_type = self.breakpoint_type.as_str();
        
        write!(f, "Breakpoint at {} ({} {})", self.get_description(), status, bp_type)?;
        
        if self.hit_count > 0 {
            write!(f, ", hit {} time(s)", self.hit_count)?;
        }
        
        if self.ignore_count > 0 {
            write!(f, ", ignore {} time(s)", self.ignore_count)?;
        }
        
        if let Some(condition) = &self.condition {
            write!(f, ", condition: {}", condition)?;
        }
        
        Ok(())
    }
}

/// Trait for evaluating breakpoint conditions
pub trait ConditionEvaluator {
    /// Evaluate a condition expression in the context of the program being debugged
    fn evaluate_condition(&self, expression: &str) -> Result<bool>;
}

/// A collection of breakpoints
#[derive(Debug, Default)]
pub struct BreakpointManager {
    /// Breakpoints by address
    breakpoints: Vec<Breakpoint>,
    /// Next auto-assigned ID
    next_id: usize,
}

impl BreakpointManager {
    /// Create a new breakpoint manager
    pub fn new() -> Self {
        Self {
            breakpoints: Vec::new(),
            next_id: 1,
        }
    }
    
    /// Add a breakpoint
    pub fn add_breakpoint(&mut self, mut breakpoint: Breakpoint) -> usize {
        // Assign an ID if none was provided
        if breakpoint.id.is_none() {
            breakpoint.id = Some(format!("bp{}", self.next_id));
            self.next_id += 1;
        }
        
        // Add the breakpoint
        self.breakpoints.push(breakpoint);
        self.breakpoints.len() - 1
    }
    
    /// Remove a breakpoint by index
    pub fn remove_breakpoint(&mut self, index: usize) -> Option<Breakpoint> {
        if index < self.breakpoints.len() {
            Some(self.breakpoints.remove(index))
        } else {
            None
        }
    }
    
    /// Find a breakpoint by address
    pub fn find_by_address(&self, address: u64) -> Option<(usize, &Breakpoint)> {
        self.breakpoints.iter()
            .enumerate()
            .find(|(_, bp)| bp.address == address)
    }
    
    /// Find a breakpoint by ID
    pub fn find_by_id(&self, id: &str) -> Option<(usize, &Breakpoint)> {
        self.breakpoints.iter()
            .enumerate()
            .find(|(_, bp)| bp.id.as_deref() == Some(id))
    }
    
    /// Get a breakpoint by index
    pub fn get(&self, index: usize) -> Option<&Breakpoint> {
        self.breakpoints.get(index)
    }
    
    /// Get a mutable reference to a breakpoint
    pub fn get_mut(&mut self, index: usize) -> Option<&mut Breakpoint> {
        self.breakpoints.get_mut(index)
    }
    
    /// Get all breakpoints
    pub fn get_all(&self) -> &[Breakpoint] {
        &self.breakpoints
    }
    
    /// Enable all breakpoints
    pub fn enable_all(&mut self) {
        for bp in &mut self.breakpoints {
            bp.enable();
        }
    }
    
    /// Disable all breakpoints
    pub fn disable_all(&mut self) {
        for bp in &mut self.breakpoints {
            bp.disable();
        }
    }
    
    /// Clear all breakpoints
    pub fn clear(&mut self) {
        self.breakpoints.clear();
    }
    
    /// Get the number of breakpoints
    pub fn count(&self) -> usize {
        self.breakpoints.len()
    }
}
