#![allow(clippy::missing_const_for_fn)]
#![allow(clippy::must_use_candidate)]

use std::fmt;
use anyhow::Result;
use crate::platform::WatchpointType;

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
            Self::Execution => "execution",
            Self::Hardware => "hardware",
            Self::Watchpoint => "watchpoint",
            Self::OneShot => "one-shot",
            Self::Conditional => "conditional",
            Self::Logging => "logging",
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
    /// Is this a temporary breakpoint (cleared after being hit)
    is_temporary: bool,
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
            is_temporary: false,
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
            is_temporary: false,
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

    /// Set the temporary flag
    pub fn set_temp(&mut self, is_temporary: bool) {
        self.is_temporary = is_temporary;
    }
    
    /// Check if this is a temporary breakpoint
    pub fn is_temporary(&self) -> bool {
        self.is_temporary
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

    /// Find the index of a breakpoint by its address
    pub fn find_index(&self, address: u64) -> Option<usize> {
        self.breakpoints.iter().position(|bp| bp.address() == address)
    }
}

/// Represents a watchpoint in the target program
#[derive(Clone, Debug)]
pub struct Watchpoint {
    /// Memory address of the watchpoint
    address: u64,
    /// Size of the watched memory (in bytes)
    size: usize,
    /// Type of access to watch for (read, write, both)
    watchpoint_type: WatchpointType,
    /// Is the watchpoint enabled?
    enabled: bool,
    /// Hit count (how many times this watchpoint has been hit)
    hit_count: usize,
    /// Ignore count (how many hits to ignore before stopping)
    ignore_count: usize,
    /// Condition (expression to evaluate, watchpoint triggers only if true)
    condition: Option<String>,
    /// Log message for logging watchpoints
    log_message: Option<String>,
    /// Symbol name associated with this watchpoint (if any)
    symbol_name: Option<String>,
    /// Hardware register used for this watchpoint (if hardware-based)
    register_index: Option<usize>,
    /// User-provided watchpoint ID/name
    id: Option<String>,
    /// Source location of the watchpoint
    source_location: Option<(String, u32)>,
}

impl Watchpoint {
    /// Create a new watchpoint
    pub fn new(address: u64, size: usize, watchpoint_type: WatchpointType) -> Self {
        Self {
            address,
            size,
            watchpoint_type,
            enabled: true,
            hit_count: 0,
            ignore_count: 0,
            condition: None,
            log_message: None,
            symbol_name: None,
            register_index: None,
            id: None,
            source_location: None,
        }
    }
    
    /// Get the address of the watchpoint
    pub fn address(&self) -> u64 {
        self.address
    }
    
    /// Get the size of the watched memory
    pub fn size(&self) -> usize {
        self.size
    }
    
    /// Get the watchpoint type
    pub fn watchpoint_type(&self) -> WatchpointType {
        self.watchpoint_type
    }
    
    /// Check if the watchpoint is enabled
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }
    
    /// Enable the watchpoint
    pub fn enable(&mut self) {
        self.enabled = true;
    }
    
    /// Disable the watchpoint
    pub fn disable(&mut self) {
        self.enabled = false;
    }
    
    /// Get the hardware register index
    pub fn register_index(&self) -> Option<usize> {
        self.register_index
    }
    
    /// Set the hardware register index
    pub fn set_register_index(&mut self, index: Option<usize>) {
        self.register_index = index;
    }
    
    /// Increment the hit count and check if we should break
    pub fn hit(&mut self) -> bool {
        self.hit_count += 1;
        
        // Check if we should ignore this hit
        if self.hit_count <= self.ignore_count {
            return false;
        }
        
        // Always break on watchpoint hits that passed the ignore count
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
    
    /// Set a condition for the watchpoint
    pub fn set_condition(&mut self, condition: Option<String>) {
        self.condition = condition;
    }
    
    /// Get the condition
    pub fn condition(&self) -> Option<&str> {
        self.condition.as_deref()
    }
    
    /// Set a log message for the watchpoint
    pub fn set_log_message(&mut self, message: Option<String>) {
        self.log_message = message;
    }
    
    /// Get the log message
    pub fn log_message(&self) -> Option<&str> {
        self.log_message.as_deref()
    }
    
    /// Set the symbol name
    pub fn set_symbol_name(&mut self, name: Option<String>) {
        self.symbol_name = name;
    }
    
    /// Get the symbol name
    pub fn symbol_name(&self) -> Option<&str> {
        self.symbol_name.as_deref()
    }
    
    /// Set the ID
    pub fn set_id(&mut self, id: Option<String>) {
        self.id = id;
    }
    
    /// Get the ID
    pub fn id(&self) -> Option<&str> {
        self.id.as_deref()
    }
    
    /// Evaluate a condition for this watchpoint
    pub fn evaluate_condition(&self, evaluator: &dyn ConditionEvaluator) -> Result<bool> {
        if let Some(condition) = &self.condition {
            evaluator.evaluate_condition(condition)
        } else {
            // No condition means always trigger
            Ok(true)
        }
    }
    
    /// Get a description of this watchpoint
    pub fn get_description(&self) -> String {
        let mut desc = format!("Watchpoint {}: ", if let Some(id) = &self.id { id } else { "" });
        
        if let Some(name) = &self.symbol_name {
            desc.push_str(&format!("{} ", name));
        }
        
        desc.push_str(&format!("at 0x{:x}", self.address));
        desc.push_str(&format!(" (size: {} bytes)", self.size));
        desc.push_str(&format!(", type: {}", self.watchpoint_type.as_str()));
        
        if let Some(condition) = &self.condition {
            desc.push_str(&format!(", condition: {}", condition));
        }
        
        desc
    }
    
    /// Set the source location
    pub fn set_source_location(&mut self, location: Option<(String, u32)>) {
        self.source_location = location;
    }
    
    /// Get the source location
    pub fn source_location(&self) -> Option<(&str, u32)> {
        self.source_location.as_ref().map(|(file, line)| (file.as_str(), *line))
    }
    
    /// Get the hit count
    pub fn hit_count(&self) -> usize {
        self.hit_count
    }
}

impl fmt::Display for Watchpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.get_description())
    }
}

/// Manages watchpoints in a program
pub struct WatchpointManager {
    /// Watchpoints by address
    watchpoints: Vec<Watchpoint>,
    /// Next auto-assigned ID
    next_id: usize,
}

impl Default for WatchpointManager {
    fn default() -> Self {
        Self::new()
    }
}

impl WatchpointManager {
    /// Create a new watchpoint manager
    pub fn new() -> Self {
        Self {
            watchpoints: Vec::new(),
            next_id: 1,
        }
    }
    
    /// Add a watchpoint
    pub fn add_watchpoint(&mut self, mut watchpoint: Watchpoint) -> usize {
        // Assign an ID if not provided
        if watchpoint.id().is_none() {
            watchpoint.set_id(Some(format!("wp{}", self.next_id)));
            self.next_id += 1;
        }
        
        // Add the watchpoint
        self.watchpoints.push(watchpoint);
        self.watchpoints.len() - 1
    }
    
    /// Remove a watchpoint by index
    pub fn remove_watchpoint(&mut self, index: usize) -> Option<Watchpoint> {
        if index < self.watchpoints.len() {
            Some(self.watchpoints.remove(index))
        } else {
            None
        }
    }
    
    /// Find a watchpoint by address
    pub fn find_by_address(&self, address: u64) -> Option<(usize, &Watchpoint)> {
        self.watchpoints.iter().enumerate().find(|(_, wp)| {
            let start = wp.address();
            let end = start + wp.size() as u64;
            address >= start && address < end
        })
    }
    
    /// Find a watchpoint by ID
    pub fn find_by_id(&self, id: &str) -> Option<(usize, &Watchpoint)> {
        self.watchpoints.iter().enumerate().find(|(_, wp)| {
            wp.id() == Some(id)
        })
    }
    
    /// Get a watchpoint by index
    pub fn get(&self, index: usize) -> Option<&Watchpoint> {
        self.watchpoints.get(index)
    }
    
    /// Get a mutable watchpoint by index
    pub fn get_mut(&mut self, index: usize) -> Option<&mut Watchpoint> {
        self.watchpoints.get_mut(index)
    }
    
    /// Get all watchpoints
    pub fn get_all(&self) -> &[Watchpoint] {
        &self.watchpoints
    }
    
    /// Enable all watchpoints
    pub fn enable_all(&mut self) {
        for watchpoint in &mut self.watchpoints {
            watchpoint.enable();
        }
    }
    
    /// Disable all watchpoints
    pub fn disable_all(&mut self) {
        for watchpoint in &mut self.watchpoints {
            watchpoint.disable();
        }
    }
    
    /// Clear all watchpoints
    pub fn clear(&mut self) {
        self.watchpoints.clear();
    }
    
    /// Get the number of watchpoints
    pub fn count(&self) -> usize {
        self.watchpoints.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::WatchpointType;
    
    #[test]
    fn test_watchpoint_create() {
        let wp = Watchpoint::new(0x1000, 4, WatchpointType::ReadWrite);
        assert_eq!(wp.address(), 0x1000);
        assert_eq!(wp.size(), 4);
        assert_eq!(wp.watchpoint_type(), WatchpointType::ReadWrite);
        assert!(wp.is_enabled());
        assert_eq!(wp.hit_count(), 0);
        assert_eq!(wp.ignore_count(), 0);
        assert!(wp.condition().is_none());
        assert!(wp.symbol_name().is_none());
        assert!(wp.id().is_none());
        assert!(wp.source_location().is_none());
    }
    
    #[test]
    fn test_watchpoint_hit_counter() {
        let mut wp = Watchpoint::new(0x1000, 8, WatchpointType::Read);
        
        // First hit with ignore_count=0 should return true
        assert!(wp.hit());
        assert_eq!(wp.hit_count(), 1);
        
        // Set ignore count
        wp.set_ignore_count(2);
        
        // Next hit should be ignored because hit_count(2) <= ignore_count(2)
        assert!(!wp.hit());
        assert_eq!(wp.hit_count(), 2);
        
        // Next hit should trigger because hit_count(3) > ignore_count(2)
        assert!(wp.hit());
        assert_eq!(wp.hit_count(), 3);
        
        // Hit again - should always trigger now
        assert!(wp.hit());
        assert_eq!(wp.hit_count(), 4);
        
        // Reset hit count
        wp.reset_hit_count();
        assert_eq!(wp.hit_count(), 0);
    }
    
    #[test]
    fn test_watchpoint_manager() {
        let mut manager = WatchpointManager::new();
        
        // Initially empty
        assert_eq!(manager.count(), 0);
        
        // Add a watchpoint
        let wp1 = Watchpoint::new(0x1000, 4, WatchpointType::Read);
        let index = manager.add_watchpoint(wp1);
        
        // Should have one watchpoint
        assert_eq!(manager.count(), 1);
        
        // Get the watchpoint
        let wp = manager.get(index).unwrap();
        assert_eq!(wp.address(), 0x1000);
        assert_eq!(wp.size(), 4);
        
        // Find by address
        let (found_index, found_wp) = manager.find_by_address(0x1000).unwrap();
        assert_eq!(found_index, index);
        assert_eq!(found_wp.address(), 0x1000);
        
        // Find by contained address
        let (found_index, found_wp) = manager.find_by_address(0x1002).unwrap();
        assert_eq!(found_index, index);
        assert_eq!(found_wp.address(), 0x1000);
        
        // Add another watchpoint
        let wp2 = Watchpoint::new(0x2000, 8, WatchpointType::Write);
        let _index2 = manager.add_watchpoint(wp2);
        
        // Should have two watchpoints
        assert_eq!(manager.count(), 2);
        
        // Remove a watchpoint
        let removed = manager.remove_watchpoint(index).unwrap();
        assert_eq!(removed.address(), 0x1000);
        
        // Should have one watchpoint left
        assert_eq!(manager.count(), 1);
        
        // Clear all watchpoints
        manager.clear();
        assert_eq!(manager.count(), 0);
    }
    
    // Add existing breakpoint tests here as well...
}
