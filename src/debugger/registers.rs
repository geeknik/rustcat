use std::collections::HashMap;
use std::fmt;

/// ARM64 register IDs
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Register {
    // General purpose registers
    X0, X1, X2, X3, X4, X5, X6, X7,
    X8, X9, X10, X11, X12, X13, X14, X15,
    X16, X17, X18, X19, X20, X21, X22, X23,
    X24, X25, X26, X27, X28, X29, X30,
    
    // Special registers
    SP,    // Stack pointer
    PC,    // Program counter
    CPSR,  // Current program status register
    
    // FP/SIMD registers (128-bit)
    Q0, Q1, Q2, Q3, Q4, Q5, Q6, Q7,
    Q8, Q9, Q10, Q11, Q12, Q13, Q14, Q15,
    Q16, Q17, Q18, Q19, Q20, Q21, Q22, Q23,
    Q24, Q25, Q26, Q27, Q28, Q29, Q30, Q31,
}

impl Register {
    /// Get the display name of the register
    pub fn display_name(&self) -> &'static str {
        match self {
            Register::X0 => "x0",
            Register::X1 => "x1",
            Register::X2 => "x2",
            Register::X3 => "x3",
            Register::X4 => "x4",
            Register::X5 => "x5",
            Register::X6 => "x6",
            Register::X7 => "x7",
            Register::X8 => "x8",
            Register::X9 => "x9",
            Register::X10 => "x10",
            Register::X11 => "x11",
            Register::X12 => "x12",
            Register::X13 => "x13",
            Register::X14 => "x14",
            Register::X15 => "x15",
            Register::X16 => "x16",
            Register::X17 => "x17",
            Register::X18 => "x18",
            Register::X19 => "x19",
            Register::X20 => "x20",
            Register::X21 => "x21",
            Register::X22 => "x22",
            Register::X23 => "x23",
            Register::X24 => "x24",
            Register::X25 => "x25",
            Register::X26 => "x26",
            Register::X27 => "x27",
            Register::X28 => "x28",
            Register::X29 => "fp", // Frame pointer
            Register::X30 => "lr", // Link register
            Register::SP => "sp",
            Register::PC => "pc",
            Register::CPSR => "cpsr",
            Register::Q0 => "q0",
            Register::Q1 => "q1",
            Register::Q2 => "q2",
            Register::Q3 => "q3",
            Register::Q4 => "q4",
            Register::Q5 => "q5",
            Register::Q6 => "q6",
            Register::Q7 => "q7",
            Register::Q8 => "q8",
            Register::Q9 => "q9",
            Register::Q10 => "q10",
            Register::Q11 => "q11",
            Register::Q12 => "q12",
            Register::Q13 => "q13",
            Register::Q14 => "q14",
            Register::Q15 => "q15",
            Register::Q16 => "q16",
            Register::Q17 => "q17",
            Register::Q18 => "q18",
            Register::Q19 => "q19",
            Register::Q20 => "q20",
            Register::Q21 => "q21",
            Register::Q22 => "q22",
            Register::Q23 => "q23",
            Register::Q24 => "q24",
            Register::Q25 => "q25",
            Register::Q26 => "q26",
            Register::Q27 => "q27",
            Register::Q28 => "q28",
            Register::Q29 => "q29",
            Register::Q30 => "q30",
            Register::Q31 => "q31",
        }
    }
    
    /// Get the ABI name of the register (mostly for parameters and return values)
    pub fn abi_name(&self) -> Option<&'static str> {
        match self {
            Register::X0 => Some("arg1/return"),
            Register::X1 => Some("arg2"),
            Register::X2 => Some("arg3"),
            Register::X3 => Some("arg4"),
            Register::X4 => Some("arg5"),
            Register::X5 => Some("arg6"),
            Register::X6 => Some("arg7"),
            Register::X7 => Some("arg8"),
            Register::X8 => Some("indirect result"),
            Register::X9 | Register::X10 | Register::X11 | 
            Register::X12 | Register::X13 | Register::X14 | 
            Register::X15 => Some("caller saved"),
            Register::X16 => Some("IP0"),
            Register::X17 => Some("IP1"),
            Register::X18 => Some("platform register"),
            Register::X19 | Register::X20 | Register::X21 | 
            Register::X22 | Register::X23 | Register::X24 | 
            Register::X25 | Register::X26 | Register::X27 |
            Register::X28 => Some("callee saved"),
            Register::X29 => Some("frame pointer"),
            Register::X30 => Some("link register"),
            Register::SP => Some("stack pointer"),
            Register::PC => Some("program counter"),
            Register::CPSR => Some("status register"),
            _ => None,
        }
    }
    
    /// Get the register group for display purposes
    pub fn group(&self) -> RegisterGroup {
        match self {
            Register::X0 | Register::X1 | Register::X2 | Register::X3 |
            Register::X4 | Register::X5 | Register::X6 | Register::X7 |
            Register::X8 | Register::X9 | Register::X10 | Register::X11 |
            Register::X12 | Register::X13 | Register::X14 | Register::X15 |
            Register::X16 | Register::X17 | Register::X18 | Register::X19 |
            Register::X20 | Register::X21 | Register::X22 | Register::X23 |
            Register::X24 | Register::X25 | Register::X26 | Register::X27 |
            Register::X28 | Register::X29 | Register::X30 => RegisterGroup::General,
            
            Register::SP | Register::PC | Register::CPSR => RegisterGroup::Special,
            
            Register::Q0 | Register::Q1 | Register::Q2 | Register::Q3 |
            Register::Q4 | Register::Q5 | Register::Q6 | Register::Q7 |
            Register::Q8 | Register::Q9 | Register::Q10 | Register::Q11 |
            Register::Q12 | Register::Q13 | Register::Q14 | Register::Q15 |
            Register::Q16 | Register::Q17 | Register::Q18 | Register::Q19 |
            Register::Q20 | Register::Q21 | Register::Q22 | Register::Q23 |
            Register::Q24 | Register::Q25 | Register::Q26 | Register::Q27 |
            Register::Q28 | Register::Q29 | Register::Q30 | Register::Q31 => RegisterGroup::Vector,
        }
    }
    
    /// Convert from index to register (for use with ARM thread state)
    pub fn from_arm64_index(idx: usize) -> Option<Self> {
        // Map from Apple's arm_thread_state64_t indexes to our Register enum
        match idx {
            0 => Some(Register::X0),
            1 => Some(Register::X1),
            2 => Some(Register::X2),
            3 => Some(Register::X3),
            4 => Some(Register::X4),
            5 => Some(Register::X5),
            6 => Some(Register::X6),
            7 => Some(Register::X7),
            8 => Some(Register::X8),
            9 => Some(Register::X9),
            10 => Some(Register::X10),
            11 => Some(Register::X11),
            12 => Some(Register::X12),
            13 => Some(Register::X13),
            14 => Some(Register::X14),
            15 => Some(Register::X15),
            16 => Some(Register::X16),
            17 => Some(Register::X17),
            18 => Some(Register::X18),
            19 => Some(Register::X19),
            20 => Some(Register::X20),
            21 => Some(Register::X21),
            22 => Some(Register::X22),
            23 => Some(Register::X23),
            24 => Some(Register::X24),
            25 => Some(Register::X25),
            26 => Some(Register::X26),
            27 => Some(Register::X27),
            28 => Some(Register::X28),
            29 => Some(Register::X29), // Frame pointer (FP)
            30 => Some(Register::X30), // Link register (LR)
            31 => Some(Register::SP),  // Stack pointer (SP)
            32 => Some(Register::PC),  // Program counter (PC)
            33 => Some(Register::CPSR), // CPSR
            _ => None,
        }
    }
    
    /// Get the arm64 thread state index for this register
    pub fn to_arm64_index(&self) -> Option<usize> {
        match self {
            Register::X0 => Some(0),
            Register::X1 => Some(1),
            Register::X2 => Some(2),
            Register::X3 => Some(3),
            Register::X4 => Some(4),
            Register::X5 => Some(5),
            Register::X6 => Some(6),
            Register::X7 => Some(7),
            Register::X8 => Some(8),
            Register::X9 => Some(9),
            Register::X10 => Some(10),
            Register::X11 => Some(11),
            Register::X12 => Some(12),
            Register::X13 => Some(13),
            Register::X14 => Some(14),
            Register::X15 => Some(15),
            Register::X16 => Some(16),
            Register::X17 => Some(17),
            Register::X18 => Some(18),
            Register::X19 => Some(19),
            Register::X20 => Some(20),
            Register::X21 => Some(21),
            Register::X22 => Some(22),
            Register::X23 => Some(23),
            Register::X24 => Some(24),
            Register::X25 => Some(25),
            Register::X26 => Some(26),
            Register::X27 => Some(27),
            Register::X28 => Some(28),
            Register::X29 => Some(29),
            Register::X30 => Some(30),
            Register::SP => Some(31),
            Register::PC => Some(32),
            Register::CPSR => Some(33),
            _ => None, // SIMD registers use a different state type
        }
    }
    
    /// Get all general purpose registers
    pub fn general_purpose_registers() -> Vec<Register> {
        vec![
            Register::X0, Register::X1, Register::X2, Register::X3,
            Register::X4, Register::X5, Register::X6, Register::X7,
            Register::X8, Register::X9, Register::X10, Register::X11,
            Register::X12, Register::X13, Register::X14, Register::X15,
            Register::X16, Register::X17, Register::X18, Register::X19,
            Register::X20, Register::X21, Register::X22, Register::X23,
            Register::X24, Register::X25, Register::X26, Register::X27,
            Register::X28, Register::X29, Register::X30,
        ]
    }
    
    /// Get all special registers
    pub fn special_registers() -> Vec<Register> {
        vec![Register::SP, Register::PC, Register::CPSR]
    }
    
    /// Get all SIMD registers
    pub fn simd_registers() -> Vec<Register> {
        vec![
            Register::Q0, Register::Q1, Register::Q2, Register::Q3,
            Register::Q4, Register::Q5, Register::Q6, Register::Q7,
            Register::Q8, Register::Q9, Register::Q10, Register::Q11,
            Register::Q12, Register::Q13, Register::Q14, Register::Q15,
            Register::Q16, Register::Q17, Register::Q18, Register::Q19,
            Register::Q20, Register::Q21, Register::Q22, Register::Q23,
            Register::Q24, Register::Q25, Register::Q26, Register::Q27,
            Register::Q28, Register::Q29, Register::Q30, Register::Q31,
        ]
    }
}

impl fmt::Display for Register {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.display_name())
    }
}

/// Register grouping for display purposes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegisterGroup {
    /// General purpose registers (X0-X30)
    General,
    /// Special registers (SP, PC, CPSR)
    Special,
    /// Vector/SIMD registers (Q0-Q31)
    Vector,
}

impl fmt::Display for RegisterGroup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RegisterGroup::General => write!(f, "General Purpose"),
            RegisterGroup::Special => write!(f, "Special"),
            RegisterGroup::Vector => write!(f, "Vector/SIMD"),
        }
    }
}

/// Register values for a thread
pub struct Registers {
    /// Register values
    values: HashMap<Register, u64>,
    /// Dirty registers (modified since last stop)
    dirty: HashMap<Register, bool>,
}

impl Registers {
    /// Create a new empty register set
    pub fn new() -> Self {
        Self {
            values: HashMap::new(),
            dirty: HashMap::new(),
        }
    }
    
    /// Set a register value
    pub fn set(&mut self, reg: Register, value: u64) {
        // Check if this is a change
        if let Some(old_value) = self.values.get(&reg) {
            if *old_value != value {
                self.dirty.insert(reg, true);
            }
        }
        
        self.values.insert(reg, value);
    }
    
    /// Get a register value
    pub fn get(&self, reg: Register) -> Option<u64> {
        self.values.get(&reg).copied()
    }
    
    /// Get a reference to the entire register value map
    pub fn get_all(&self) -> &HashMap<Register, u64> {
        &self.values
    }
    
    /// Update multiple registers at once
    pub fn update(&mut self, updates: HashMap<Register, u64>) {
        for (reg, value) in updates {
            self.set(reg, value);
        }
    }
    
    /// Mark all registers as clean (not modified)
    pub fn clear_dirty(&mut self) {
        self.dirty.clear();
    }
    
    /// Clear all register values
    pub fn clear(&mut self) {
        self.values.clear();
        self.dirty.clear();
    }
    
    /// Get the stack pointer value
    pub fn get_stack_pointer(&self) -> Option<u64> {
        self.get(Register::SP)
    }
    
    /// Get the program counter value
    pub fn get_program_counter(&self) -> Option<u64> {
        self.get(Register::PC)
    }
    
    /// Get the link register (return address)
    pub fn get_link_register(&self) -> Option<u64> {
        self.get(Register::X30)
    }
    
    /// Get the frame pointer
    pub fn get_frame_pointer(&self) -> Option<u64> {
        self.get(Register::X29)
    }
    
    /// Format a register value as a hex string
    pub fn format_value(&self, reg: Register) -> String {
        match self.get(reg) {
            Some(value) => format!("0x{:016x}", value),
            None => "N/A".to_string(),
        }
    }
    
    /// Check if a register is dirty (modified since last stop)
    pub fn is_dirty(&self, reg: Register) -> bool {
        self.dirty.get(&reg).copied().unwrap_or(false)
    }
    
    /// Get all registers in a specific group
    pub fn get_registers_by_group(&self, group: RegisterGroup) -> Vec<(Register, Option<u64>)> {
        let registers = match group {
            RegisterGroup::General => Register::general_purpose_registers(),
            RegisterGroup::Special => Register::special_registers(),
            RegisterGroup::Vector => Register::simd_registers(),
        };
        
        registers.into_iter()
            .map(|reg| (reg, self.get(reg)))
            .collect()
    }
}

impl Default for Registers {
    fn default() -> Self {
        Self::new()
    }
}
