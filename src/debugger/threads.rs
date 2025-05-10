use std::collections::HashMap;

use crate::debugger::registers::Registers;

/// Information about a thread in the target process
pub struct Thread {
    /// Thread ID
    tid: u64,
    /// Thread name (if available)
    name: Option<String>,
    /// Is this the main thread?
    is_main: bool,
    /// Current register values
    registers: Option<Registers>,
}

impl Thread {
    /// Create a new thread
    pub fn new(tid: u64, name: Option<String>, is_main: bool) -> Self {
        Self {
            tid,
            name,
            is_main,
            registers: None,
        }
    }
    
    /// Get the thread ID
    pub fn tid(&self) -> u64 {
        self.tid
    }
    
    /// Get the thread name
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }
    
    /// Check if this is the main thread
    pub fn is_main(&self) -> bool {
        self.is_main
    }
    
    /// Get a reference to the thread's registers
    pub fn registers(&self) -> Option<&Registers> {
        self.registers.as_ref()
    }
    
    /// Get a mutable reference to the thread's registers
    pub fn registers_mut(&mut self) -> Option<&mut Registers> {
        self.registers.as_mut()
    }
    
    /// Set the thread's registers
    pub fn set_registers(&mut self, registers: Registers) {
        self.registers = Some(registers);
    }
}

/// Thread manager for the target process
pub struct ThreadManager {
    /// Threads by ID
    threads: HashMap<u64, Thread>,
    /// ID of the current thread
    current_thread: Option<u64>,
}

impl ThreadManager {
    /// Create a new thread manager
    pub fn new() -> Self {
        Self {
            threads: HashMap::new(),
            current_thread: None,
        }
    }
    
    /// Add a thread
    pub fn add_thread(&mut self, thread: Thread) {
        let tid = thread.tid();
        
        // If this is the first thread, make it the current thread
        if self.threads.is_empty() {
            self.current_thread = Some(tid);
        }
        
        self.threads.insert(tid, thread);
    }
    
    /// Remove a thread
    pub fn remove_thread(&mut self, tid: u64) {
        self.threads.remove(&tid);
        
        // If the current thread was removed, select a new one
        if self.current_thread == Some(tid) {
            self.current_thread = self.threads.keys().next().copied();
        }
    }
    
    /// Get a reference to a thread by ID
    pub fn get_thread(&self, tid: u64) -> Option<&Thread> {
        self.threads.get(&tid)
    }
    
    /// Get a mutable reference to a thread by ID
    pub fn get_thread_mut(&mut self, tid: u64) -> Option<&mut Thread> {
        self.threads.get_mut(&tid)
    }
    
    /// Get a reference to the current thread
    pub fn current_thread(&self) -> Option<&Thread> {
        self.current_thread.and_then(|tid| self.get_thread(tid))
    }
    
    /// Get a mutable reference to the current thread
    pub fn current_thread_mut(&mut self) -> Option<&mut Thread> {
        let tid = self.current_thread?;
        self.get_thread_mut(tid)
    }
    
    /// Get a reference to all threads
    pub fn get_all_threads(&self) -> &HashMap<u64, Thread> {
        &self.threads
    }
    
    /// Set the current thread
    pub fn set_current_thread(&mut self, tid: u64) -> bool {
        if self.threads.contains_key(&tid) {
            self.current_thread = Some(tid);
            true
        } else {
            false
        }
    }
    
    /// Update the list of threads
    pub fn update_threads(&mut self, tids: Vec<u64>) {
        // Remove threads that are no longer running
        self.threads.retain(|&tid, _| tids.contains(&tid));
        
        // Add new threads
        for tid in tids {
            if !self.threads.contains_key(&tid) {
                let thread = Thread::new(tid, None, false);
                self.add_thread(thread);
            }
        }
    }
    
    /// Clear all threads
    pub fn clear(&mut self) {
        self.threads.clear();
        self.current_thread = None;
    }
}

impl Default for ThreadManager {
    fn default() -> Self {
        Self::new()
    }
}
