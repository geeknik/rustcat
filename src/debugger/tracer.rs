use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};
use std::sync::{Arc, Mutex};
use anyhow::{Result, anyhow};
use log::{debug, info, error};

/// Represents a function call in the trace
#[derive(Debug, Clone)]
pub struct FunctionCall {
    /// The address where the function was called
    pub call_site: u64,
    /// The entry point of the called function
    pub function_address: u64,
    /// The name of the function (if known)
    pub function_name: Option<String>,
    /// The time when the function was called
    pub call_time: Instant,
    /// The time when the function returned (if it has)
    pub return_time: Option<Instant>,
    /// The thread ID that made the call
    pub thread_id: u64,
    /// The call depth (0 = root call)
    pub depth: usize,
    /// The return value (if any and if known)
    pub return_value: Option<u64>,
    /// Arguments passed to the function (if known)
    pub arguments: Vec<(String, String)>, // (name, value)
    /// Children function calls
    pub children: Vec<usize>, // Indices into the parent's call list
}

impl FunctionCall {
    /// Create a new function call record
    pub fn new(call_site: u64, function_address: u64, thread_id: u64, depth: usize) -> Self {
        Self {
            call_site,
            function_address,
            function_name: None,
            call_time: Instant::now(),
            return_time: None,
            thread_id,
            depth,
            return_value: None,
            arguments: Vec::new(),
            children: Vec::new(),
        }
    }

    /// Mark this function call as returned
    pub fn mark_returned(&mut self, return_value: Option<u64>) {
        self.return_time = Some(Instant::now());
        self.return_value = return_value;
    }

    /// Get the duration of this function call
    pub fn duration(&self) -> Option<Duration> {
        self.return_time.map(|rt| rt.duration_since(self.call_time))
    }

    /// Add a function argument
    pub fn add_argument(&mut self, name: String, value: String) {
        self.arguments.push((name, value));
    }

    /// Set the function name
    pub fn set_function_name(&mut self, name: String) {
        self.function_name = Some(name);
    }
    
    /// Get a formatted representation of this function call
    pub fn format(&self) -> String {
        let name = self.function_name.as_deref().unwrap_or("unknown");
        let indent = "  ".repeat(self.depth);
        
        let duration = if let Some(duration) = self.duration() {
            format!(" ({}ms)", duration.as_millis())
        } else {
            " (active)".to_string()
        };
        
        let args_str = if self.arguments.is_empty() {
            "()".to_string()
        } else {
            let args: Vec<String> = self.arguments.iter()
                .map(|(name, value)| format!("{}: {}", name, value))
                .collect();
            format!("({})", args.join(", "))
        };
        
        format!("{}→ {}{}{}", indent, name, args_str, duration)
    }
}

/// Function call tracer to record function entry and exit
pub struct FunctionTracer {
    /// All recorded function calls
    calls: Vec<FunctionCall>,
    /// Call stack per thread, stores indices into the calls vector
    call_stacks: HashMap<u64, Vec<usize>>,
    /// Track the current call depth per thread
    depths: HashMap<u64, usize>,
    /// Maximum number of calls to store
    max_calls: usize,
    /// Whether tracing is enabled
    enabled: bool,
    /// Filters for which functions to trace
    function_filters: Vec<String>,
    /// Lookup cache for function names by address
    address_to_name: HashMap<u64, String>,
    /// Maximum call stack depth to trace
    max_depth: usize,
    /// Symbol resolver for looking up function names
    symbol_resolver: Option<Arc<Mutex<crate::debugger::symbols::SymbolTable>>>,
}

impl FunctionTracer {
    /// Create a new function tracer
    pub fn new() -> Self {
        Self {
            calls: Vec::new(),
            call_stacks: HashMap::new(),
            depths: HashMap::new(),
            max_calls: 10000, // Default, can be changed
            enabled: false,
            function_filters: Vec::new(),
            address_to_name: HashMap::new(),
            max_depth: 100,
            symbol_resolver: None,
        }
    }
    
    /// Set the symbol resolver for looking up function names
    pub fn set_symbol_resolver(&mut self, resolver: Arc<Mutex<crate::debugger::symbols::SymbolTable>>) {
        self.symbol_resolver = Some(resolver);
    }

    /// Enable function call tracing
    pub fn enable(&mut self) {
        self.enabled = true;
        info!("Function call tracing enabled");
    }

    /// Disable function call tracing
    pub fn disable(&mut self) {
        self.enabled = false;
        info!("Function call tracing disabled");
    }

    /// Clear all recorded function calls
    pub fn clear(&mut self) {
        self.calls.clear();
        self.call_stacks.clear();
        self.depths.clear();
        info!("Function call trace cleared");
    }

    /// Set the maximum number of calls to store
    pub fn set_max_calls(&mut self, max_calls: usize) {
        self.max_calls = max_calls;
    }

    /// Set the maximum call stack depth to trace
    pub fn set_max_depth(&mut self, max_depth: usize) {
        self.max_depth = max_depth;
    }

    /// Add a function filter (only trace functions matching these patterns)
    pub fn add_function_filter(&mut self, pattern: String) {
        let pattern_copy = pattern.clone();
        self.function_filters.push(pattern);
        info!("Added function trace filter: {}", pattern_copy);
    }

    /// Clear all function filters
    pub fn clear_function_filters(&mut self) {
        self.function_filters.clear();
        info!("Cleared all function trace filters");
    }

    /// Record a function call
    pub fn record_call(&mut self, call_site: u64, function_address: u64, thread_id: u64) -> Result<usize> {
        if !self.enabled {
            return Err(anyhow!("Function call tracing is disabled"));
        }

        // Get and update the call depth for this thread
        let depth = *self.depths.entry(thread_id).or_insert(0);
        
        // Check if we've exceeded the max depth
        if depth >= self.max_depth {
            return Err(anyhow!("Maximum call depth exceeded"));
        }
        
        // Increment the depth for this thread
        *self.depths.get_mut(&thread_id).unwrap() += 1;

        // Look up the function name
        let function_name = self.resolve_function_name(function_address);
        
        // Create a new function call record
        let mut call = FunctionCall::new(call_site, function_address, thread_id, depth);
        
        // Set the function name if known
        if let Some(name) = function_name {
            call.set_function_name(name);
        }
        
        // Check if we should store this call based on filters
        if !self.function_filters.is_empty() {
            let fn_name = call.function_name.as_deref().unwrap_or("unknown");
            
            // Check if any filter matches this function name
            let should_trace = self.function_filters.iter()
                .any(|filter| fn_name.contains(filter));
            
            if !should_trace {
                // Skip this call, but maintain the depth counter
                return Err(anyhow!("Function didn't match any filters"));
            }
        }
        
        // Add this call to the list
        self.calls.push(call);
        let call_idx = self.calls.len() - 1;
        
        // Maintain the call stack for this thread
        let call_stack = self.call_stacks.entry(thread_id).or_insert_with(Vec::new);
        
        // If this isn't the first call in the stack, add it as a child of the parent
        if let Some(&parent_idx) = call_stack.last() {
            if let Some(parent) = self.calls.get_mut(parent_idx) {
                parent.children.push(call_idx);
            }
        }
        
        // Push this call onto the stack
        call_stack.push(call_idx);
        
        // Trim the calls list if it gets too large
        if self.calls.len() > self.max_calls {
            self.calls.remove(0);
            // This invalidates all indices, but it's a reasonable compromise
            // for keeping memory usage bounded
            debug!("Function call trace exceeded max size, oldest call removed");
        }
        
        Ok(call_idx)
    }

    /// Record a function return
    pub fn record_return(&mut self, thread_id: u64, return_value: Option<u64>) -> Result<()> {
        if !self.enabled {
            return Err(anyhow!("Function call tracing is disabled"));
        }

        // Decrease the depth for this thread
        if let Some(depth) = self.depths.get_mut(&thread_id) {
            if *depth > 0 {
                *depth -= 1;
            }
        }

        // Pop the most recent call for this thread
        if let Some(call_stack) = self.call_stacks.get_mut(&thread_id) {
            if let Some(call_idx) = call_stack.pop() {
                // Mark the call as returned
                if let Some(call) = self.calls.get_mut(call_idx) {
                    call.mark_returned(return_value);
                }
                Ok(())
            } else {
                Err(anyhow!("No active function call for thread {}", thread_id))
            }
        } else {
            Err(anyhow!("No call stack for thread {}", thread_id))
        }
    }

    /// Get all recorded function calls
    pub fn get_calls(&self) -> &[FunctionCall] {
        &self.calls
    }

    /// Get the active call stack for a thread
    pub fn get_call_stack(&self, thread_id: u64) -> Vec<&FunctionCall> {
        if let Some(call_stack) = self.call_stacks.get(&thread_id) {
            call_stack.iter()
                .filter_map(|&idx| self.calls.get(idx))
                .collect()
        } else {
            Vec::new()
        }
    }

    /// Check if tracing is enabled
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Get call statistics
    pub fn get_statistics(&self) -> HashMap<String, (usize, Duration)> {
        let mut stats: HashMap<String, (usize, Duration)> = HashMap::new();
        
        for call in &self.calls {
            if let (Some(name), Some(duration)) = (&call.function_name, call.duration()) {
                let entry = stats.entry(name.clone()).or_insert((0, Duration::ZERO));
                entry.0 += 1; // Increment count
                entry.1 += duration; // Add duration
            }
        }
        
        stats
    }

    /// Resolve a function name from an address
    fn resolve_function_name(&mut self, address: u64) -> Option<String> {
        // Check cache first
        if let Some(name) = self.address_to_name.get(&address) {
            return Some(name.clone());
        }
        
        // Try to resolve from symbols
        if let Some(resolver) = &self.symbol_resolver {
            if let Ok(resolver) = resolver.lock() {
                if let Some(symbol) = resolver.find_by_address_range(address) {
                    let name = symbol.display_name().to_string();
                    // Cache the result
                    self.address_to_name.insert(address, name.clone());
                    return Some(name);
                }
            }
        }
        
        None
    }
    
    /// Get a formatted call tree for a thread
    pub fn format_call_tree(&self, thread_id: u64) -> Vec<String> {
        let mut result = Vec::new();
        
        // Find the root calls (depth 0) for this thread
        for (i, call) in self.calls.iter().enumerate() {
            if call.thread_id == thread_id && call.depth == 0 {
                // This is a root call, format its subtree
                self.format_subtree(i, &mut result);
            }
        }
        
        result
    }
    
    /// Format a subtree of calls starting at the given index
    fn format_subtree(&self, call_idx: usize, result: &mut Vec<String>) {
        if let Some(call) = self.calls.get(call_idx) {
            result.push(call.format());
            
            // Process children
            for &child_idx in &call.children {
                self.format_subtree(child_idx, result);
            }
        }
    }
}

impl Default for FunctionTracer {
    fn default() -> Self {
        Self::new()
    }
} 