use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::time::{Duration, Instant};

use anyhow::Result;
use log::{debug, info, warn};

use crate::debugger::registers::Registers;

/// Thread state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreadState {
    /// Thread is running
    Running,
    /// Thread is stopped by the debugger
    Stopped,
    /// Thread is stopped at a breakpoint
    AtBreakpoint,
    /// Thread is stopped by a signal
    SignalStop(i32),
    /// Thread is suspended by the debugger
    Suspended,
    /// Thread is waiting on a resource
    Waiting,
    /// Thread is blocked on I/O
    Blocked,
    /// Thread has exited
    Exited(i32), // Exit code
}

impl ThreadState {
    /// Check if the thread is stopped in any way
    pub fn is_stopped(&self) -> bool {
        matches!(
            self,
            ThreadState::Stopped | ThreadState::AtBreakpoint | ThreadState::SignalStop(_) | ThreadState::Suspended
        )
    }
    
    /// Check if the thread is running
    pub fn is_running(&self) -> bool {
        matches!(self, ThreadState::Running)
    }
    
    /// Check if the thread has exited
    pub fn is_exited(&self) -> bool {
        matches!(self, ThreadState::Exited(_))
    }
    
    /// Get a human-readable description of the state
    pub fn description(&self) -> String {
        match self {
            ThreadState::Running => "running".to_string(),
            ThreadState::Stopped => "stopped".to_string(),
            ThreadState::AtBreakpoint => "at breakpoint".to_string(),
            ThreadState::SignalStop(signal) => format!("signal stop ({})", signal),
            ThreadState::Suspended => "suspended".to_string(),
            ThreadState::Waiting => "waiting".to_string(),
            ThreadState::Blocked => "blocked".to_string(),
            ThreadState::Exited(code) => format!("exited ({})", code),
        }
    }
}

impl fmt::Display for ThreadState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.description())
    }
}

/// A stack frame in a thread's call stack
#[derive(Debug, Clone)]
pub struct StackFrame {
    /// Frame number (0 is the innermost frame)
    pub number: usize,
    /// Instruction pointer
    pub pc: u64,
    /// Stack pointer
    pub sp: u64,
    /// Frame pointer
    pub fp: u64,
    /// Function name (if known)
    pub function: Option<String>,
    /// Source file (if known)
    pub source_file: Option<String>,
    /// Line number (if known)
    pub line: Option<u32>,
    /// Argument values (if known)
    pub arguments: Vec<(String, String)>, // (name, value)
    /// Local variables (if known)
    pub locals: Vec<(String, String)>, // (name, value)
}

impl StackFrame {
    /// Create a new stack frame
    pub fn new(number: usize, pc: u64, sp: u64, fp: u64) -> Self {
        Self {
            number,
            pc,
            sp,
            fp,
            function: None,
            source_file: None,
            line: None,
            arguments: Vec::new(),
            locals: Vec::new(),
        }
    }
    
    /// Set the function name
    pub fn with_function(mut self, function: String) -> Self {
        self.function = Some(function);
        self
    }
    
    /// Set the source location
    pub fn with_source_location(mut self, file: String, line: u32) -> Self {
        self.source_file = Some(file);
        self.line = Some(line);
        self
    }
    
    /// Add an argument
    pub fn add_argument(&mut self, name: String, value: String) {
        self.arguments.push((name, value));
    }
    
    /// Add a local variable
    pub fn add_local(&mut self, name: String, value: String) {
        self.locals.push((name, value));
    }
    
    /// Get a descriptive string for the frame
    pub fn description(&self) -> String {
        let location = if let Some(function) = &self.function {
            if let (Some(file), Some(line)) = (&self.source_file, self.line) {
                format!("{} at {}:{}", function, file, line)
            } else {
                function.clone()
            }
        } else {
            format!("0x{:x}", self.pc)
        };
        
        format!("#{} {}", self.number, location)
    }
}

/// Thread CPU time tracking
#[derive(Debug, Clone)]
pub struct ThreadTiming {
    /// When the thread was created
    pub creation_time: Instant,
    /// Total CPU time used (user + system)
    pub cpu_time: Duration,
    /// User-mode CPU time
    pub user_time: Duration,
    /// System-mode CPU time
    pub system_time: Duration,
    /// When the CPU usage was last updated
    pub last_update: Instant,
}

impl ThreadTiming {
    /// Create new thread timing information
    #[allow(dead_code)]
    pub fn new() -> Self {
        let now = Instant::now();
        Self {
            creation_time: now,
            cpu_time: Duration::from_secs(0),
            user_time: Duration::from_secs(0),
            system_time: Duration::from_secs(0),
            last_update: now,
        }
    }
    
    /// Update CPU usage
    pub fn update(&mut self, user_time: Duration, system_time: Duration) {
        self.user_time = user_time;
        self.system_time = system_time;
        self.cpu_time = user_time + system_time;
        self.last_update = Instant::now();
    }
    
    /// Get time since thread creation
    pub fn lifetime(&self) -> Duration {
        Instant::now().duration_since(self.creation_time)
    }
}

impl Default for ThreadTiming {
    fn default() -> Self {
        Self::new()
    }
}

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
    /// Thread state
    state: ThreadState,
    /// Call stack
    call_stack: Vec<StackFrame>,
    /// Thread timing information
    timing: ThreadTiming,
    /// Thread-specific breakpoints (only hit in this thread)
    thread_breakpoints: Vec<u64>,
    /// Reason for stopping
    stop_reason: Option<String>,
    /// Event history for this thread
    event_history: VecDeque<(Instant, String)>,
    /// Maximum event history size
    max_history_size: usize,
}

impl Thread {
    /// Create a new thread
    pub fn new(tid: u64, name: Option<String>, is_main: bool) -> Self {
        Self {
            tid,
            name,
            is_main,
            registers: None,
            state: ThreadState::Running,
            call_stack: Vec::new(),
            timing: ThreadTiming::new(),
            thread_breakpoints: Vec::new(),
            stop_reason: None,
            event_history: VecDeque::new(),
            max_history_size: 100,
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
    
    /// Set the thread name
    pub fn set_name(&mut self, name: Option<String>) {
        self.name = name;
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
    
    /// Get the thread state
    pub fn state(&self) -> ThreadState {
        self.state
    }
    
    /// Set the thread state
    pub fn set_state(&mut self, state: ThreadState) {
        let old_state = self.state;
        self.state = state;
        
        // Record state transition in event history
        if old_state != state {
            self.add_event(format!("State changed from {} to {}", old_state, state));
        }
    }
    
    /// Get the call stack
    pub fn call_stack(&self) -> &[StackFrame] {
        &self.call_stack
    }
    
    /// Set the call stack
    pub fn set_call_stack(&mut self, call_stack: Vec<StackFrame>) {
        self.call_stack = call_stack;
    }
    
    /// Get the thread timing information
    pub fn timing(&self) -> &ThreadTiming {
        &self.timing
    }
    
    /// Get a mutable reference to the thread timing information
    pub fn timing_mut(&mut self) -> &mut ThreadTiming {
        &mut self.timing
    }
    
    /// Add a thread-specific breakpoint
    pub fn add_breakpoint(&mut self, address: u64) {
        if !self.thread_breakpoints.contains(&address) {
            self.thread_breakpoints.push(address);
            self.add_event(format!("Added thread-specific breakpoint at 0x{:x}", address));
        }
    }
    
    /// Remove a thread-specific breakpoint
    pub fn remove_breakpoint(&mut self, address: u64) {
        if let Some(pos) = self.thread_breakpoints.iter().position(|&a| a == address) {
            self.thread_breakpoints.remove(pos);
            self.add_event(format!("Removed thread-specific breakpoint at 0x{:x}", address));
        }
    }
    
    /// Get all thread-specific breakpoints
    pub fn breakpoints(&self) -> &[u64] {
        &self.thread_breakpoints
    }
    
    /// Check if a breakpoint is specific to this thread
    pub fn has_breakpoint(&self, address: u64) -> bool {
        self.thread_breakpoints.contains(&address)
    }
    
    /// Set the stop reason
    pub fn set_stop_reason(&mut self, reason: Option<String>) {
        if reason != self.stop_reason {
            if let Some(reason_str) = &reason {
                self.add_event(format!("Thread stopped: {}", reason_str));
            }
            self.stop_reason = reason;
        }
    }
    
    /// Get the stop reason
    pub fn stop_reason(&self) -> Option<&str> {
        self.stop_reason.as_deref()
    }
    
    /// Add an event to the thread's history
    pub fn add_event(&mut self, event: String) {
        let now = Instant::now();
        self.event_history.push_back((now, event));
        
        // Maintain maximum history size
        while self.event_history.len() > self.max_history_size {
            self.event_history.pop_front();
        }
    }
    
    /// Get the event history
    pub fn event_history(&self) -> &VecDeque<(Instant, String)> {
        &self.event_history
    }
    
    /// Get the thread's current frame (top of the stack)
    pub fn current_frame(&self) -> Option<&StackFrame> {
        self.call_stack.first()
    }
    
    /// Get a descriptive string for this thread
    pub fn description(&self) -> String {
        let name_part = if let Some(name) = &self.name {
            format!("{} ({})", name, self.tid)
        } else {
            format!("Thread {}", self.tid)
        };
        
        let state_part = self.state.description();
        
        if let Some(reason) = &self.stop_reason {
            format!("{}: {} - {}", name_part, state_part, reason)
        } else {
            format!("{}: {}", name_part, state_part)
        }
    }
}

/// Thread creation information
#[derive(Debug, Clone)]
pub struct ThreadCreationInfo {
    /// Thread ID
    pub tid: u64,
    /// Thread name (if available)
    pub name: Option<String>,
    /// Parent thread ID (if known)
    pub parent_tid: Option<u64>,
    /// Creation time
    pub time: Instant,
    /// Initial stack pointer
    pub stack_pointer: Option<u64>,
    /// Initial instruction pointer
    pub instruction_pointer: Option<u64>,
}

/// Thread manager for the target process
pub struct ThreadManager {
    /// Threads by ID
    threads: HashMap<u64, Thread>,
    /// ID of the current thread
    current_thread: Option<u64>,
    /// History of thread creations
    creation_history: Vec<ThreadCreationInfo>,
    /// Enable thread-specific breakpoints
    enable_thread_breakpoints: bool,
    /// Lock new threads on creation (start suspended)
    lock_new_threads: bool,
}

impl ThreadManager {
    /// Create a new thread manager
    pub fn new() -> Self {
        Self {
            threads: HashMap::new(),
            current_thread: None,
            creation_history: Vec::new(),
            enable_thread_breakpoints: true,
            lock_new_threads: false,
        }
    }
    
    /// Add a thread
    pub fn add_thread(&mut self, mut thread: Thread) -> Result<()> {
        let tid = thread.tid();
        
        // Record thread creation
        let creation_info = ThreadCreationInfo {
            tid,
            name: thread.name().map(|s| s.to_string()),
            parent_tid: None, // Not known yet
            time: Instant::now(),
            stack_pointer: thread.registers().and_then(|r| r.get_stack_pointer()),
            instruction_pointer: thread.registers().and_then(|r| r.get_program_counter()),
        };
        self.creation_history.push(creation_info);
        
        // Set initial state if locking new threads
        if self.lock_new_threads {
            thread.set_state(ThreadState::Suspended);
        }
        
        // If this is the first thread, make it the current thread
        if self.threads.is_empty() {
            self.current_thread = Some(tid);
        }
        
        // Log thread creation
        info!("Thread {} created{}", tid, 
             if let Some(name) = thread.name() { format!(" ({})", name) } else { String::new() });
        
        self.threads.insert(tid, thread);
        Ok(())
    }
    
    /// Remove a thread
    pub fn remove_thread(&mut self, tid: u64) -> Result<Option<Thread>> {
        // Log thread removal
        if let Some(thread) = self.threads.get(&tid) {
            info!("Thread {} removed{}", tid,
                 if let Some(name) = thread.name() { format!(" ({})", name) } else { String::new() });
        }
        
        let thread = self.threads.remove(&tid);
        
        // If the current thread was removed, select a new one
        if self.current_thread == Some(tid) {
            self.current_thread = self.threads.keys().next().copied();
        }
        
        Ok(thread)
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
    
    /// Get the current thread ID
    pub fn current_thread_id(&self) -> Option<u64> {
        self.current_thread
    }
    
    /// Set the current thread
    pub fn set_current_thread(&mut self, tid: u64) -> Result<bool> {
        if self.threads.contains_key(&tid) {
            let old_thread = self.current_thread;
            self.current_thread = Some(tid);
            
            // Log current thread change
            if old_thread != self.current_thread {
                debug!("Current thread changed from {:?} to {}", old_thread, tid);
            }
            
            Ok(true)
        } else {
            warn!("Attempted to set current thread to non-existent thread {}", tid);
            Ok(false)
        }
    }
    
    /// Update the state of a thread
    pub fn update_thread_state(&mut self, tid: u64, state: ThreadState) -> Result<bool> {
        if let Some(thread) = self.threads.get_mut(&tid) {
            thread.set_state(state);
            Ok(true)
        } else {
            Ok(false)
        }
    }
    
    /// Update the list of threads
    pub fn update_threads(&mut self, tids: Vec<u64>) -> Result<()> {
        // Make a list of threads to remove (not in the new list)
        let threads_to_remove: Vec<_> = self.threads.keys()
            .filter(|&&tid| !tids.contains(&tid))
            .copied()
            .collect();
        
        // Remove threads that are no longer running
        for tid in threads_to_remove {
            self.remove_thread(tid)?;
        }
        
        // Add new threads
        for tid in tids {
            if !self.threads.contains_key(&tid) {
                let thread = Thread::new(tid, None, false);
                self.add_thread(thread)?;
            }
        }
        
        Ok(())
    }
    
    /// Get threads in the given state
    pub fn get_threads_by_state(&self, state: ThreadState) -> Vec<&Thread> {
        self.threads.values()
            .filter(|thread| thread.state() == state)
            .collect()
    }
    
    /// Suspend all threads
    pub fn suspend_all_threads(&mut self) {
        for thread in self.threads.values_mut() {
            if thread.state().is_running() {
                thread.set_state(ThreadState::Suspended);
                thread.add_event("Suspended by debugger".to_string());
            }
        }
    }
    
    /// Resume all threads
    pub fn resume_all_threads(&mut self) {
        for thread in self.threads.values_mut() {
            if thread.state() == ThreadState::Suspended {
                thread.set_state(ThreadState::Running);
                thread.add_event("Resumed by debugger".to_string());
            }
        }
    }
    
    /// Resume a specific thread
    pub fn resume_thread(&mut self, tid: u64) -> Result<bool> {
        if let Some(thread) = self.threads.get_mut(&tid) {
            if thread.state() == ThreadState::Suspended || thread.state().is_stopped() {
                thread.set_state(ThreadState::Running);
                thread.add_event("Resumed by debugger".to_string());
                Ok(true)
            } else {
                // Thread is not suspended
                Ok(false)
            }
        } else {
            // Thread not found
            Ok(false)
        }
    }
    
    /// Suspend a specific thread
    pub fn suspend_thread(&mut self, tid: u64) -> Result<bool> {
        if let Some(thread) = self.threads.get_mut(&tid) {
            if thread.state().is_running() {
                thread.set_state(ThreadState::Suspended);
                thread.add_event("Suspended by debugger".to_string());
                Ok(true)
            } else {
                // Thread is already suspended or stopped
                Ok(false)
            }
        } else {
            // Thread not found
            Ok(false)
        }
    }
    
    /// Check if any thread is at a breakpoint
    pub fn any_thread_at_breakpoint(&self) -> bool {
        self.threads.values().any(|thread| thread.state() == ThreadState::AtBreakpoint)
    }
    
    /// Enable/disable thread-specific breakpoints
    pub fn set_thread_breakpoints_enabled(&mut self, enabled: bool) {
        self.enable_thread_breakpoints = enabled;
    }
    
    /// Check if thread-specific breakpoints are enabled
    pub fn are_thread_breakpoints_enabled(&self) -> bool {
        self.enable_thread_breakpoints
    }
    
    /// Enable/disable locking new threads (start suspended)
    pub fn set_lock_new_threads(&mut self, lock: bool) {
        self.lock_new_threads = lock;
    }
    
    /// Check if new threads are locked
    pub fn are_new_threads_locked(&self) -> bool {
        self.lock_new_threads
    }
    
    /// Get thread creation history
    pub fn creation_history(&self) -> &[ThreadCreationInfo] {
        &self.creation_history
    }
    
    /// Update a thread's call stack
    pub fn update_call_stack(&mut self, tid: u64, call_stack: Vec<StackFrame>) -> Result<bool> {
        if let Some(thread) = self.threads.get_mut(&tid) {
            thread.set_call_stack(call_stack);
            Ok(true)
        } else {
            Ok(false)
        }
    }
    
    /// Check if a breakpoint applies to a thread
    pub fn should_break_in_thread(&self, tid: u64, address: u64) -> bool {
        // If thread-specific breakpoints are disabled, all breakpoints apply to all threads
        if !self.enable_thread_breakpoints {
            return true;
        }
        
        // Check if this thread has any thread-specific breakpoints
        if let Some(thread) = self.threads.get(&tid) {
            if thread.breakpoints().is_empty() {
                // No thread-specific breakpoints, so all breakpoints apply
                return true;
            }
            
            // Check if this specific address is in the thread's breakpoints
            return thread.has_breakpoint(address);
        }
        
        // Thread not found, default to breaking
        true
    }
    
    /// Clear all threads
    pub fn clear(&mut self) {
        self.threads.clear();
        self.current_thread = None;
        // Don't clear creation history, as it can be useful for post-mortem analysis
    }
    
    /// Get the count of threads
    pub fn thread_count(&self) -> usize {
        self.threads.len()
    }
    
    /// Find a thread by name
    pub fn find_thread_by_name(&self, name: &str) -> Option<&Thread> {
        self.threads.values().find(|thread| {
            if let Some(thread_name) = thread.name() {
                thread_name == name
            } else {
                false
            }
        })
    }
}

impl Default for ThreadManager {
    fn default() -> Self {
        Self::new()
    }
}
