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
    Sp,    // Stack pointer
    Pc,    // Program counter
    #[allow(dead_code)]
    Lr,    // Link register
    Cpsr,  // Current program status register
    
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
            Self::X0 => "x0",
            Self::X1 => "x1",
            Self::X2 => "x2",
            Self::X3 => "x3",
            Self::X4 => "x4",
            Self::X5 => "x5",
            Self::X6 => "x6",
            Self::X7 => "x7",
            Self::X8 => "x8",
            Self::X9 => "x9",
            Self::X10 => "x10",
            Self::X11 => "x11",
            Self::X12 => "x12",
            Self::X13 => "x13",
            Self::X14 => "x14",
            Self::X15 => "x15",
            Self::X16 => "x16",
            Self::X17 => "x17",
            Self::X18 => "x18",
            Self::X19 => "x19",
            Self::X20 => "x20",
            Self::X21 => "x21",
            Self::X22 => "x22",
            Self::X23 => "x23",
            Self::X24 => "x24",
            Self::X25 => "x25",
            Self::X26 => "x26",
            Self::X27 => "x27",
            Self::X28 => "x28",
            Self::X29 => "fp", // Frame pointer
            Self::X30 => "lr", // Link register
            Self::Sp => "sp",
            Self::Pc => "pc",
            Self::Lr => "lr",
            Self::Cpsr => "cpsr",
            Self::Q0 => "q0",
            Self::Q1 => "q1",
            Self::Q2 => "q2",
            Self::Q3 => "q3",
            Self::Q4 => "q4",
            Self::Q5 => "q5",
            Self::Q6 => "q6",
            Self::Q7 => "q7",
            Self::Q8 => "q8",
            Self::Q9 => "q9",
            Self::Q10 => "q10",
            Self::Q11 => "q11",
            Self::Q12 => "q12",
            Self::Q13 => "q13",
            Self::Q14 => "q14",
            Self::Q15 => "q15",
            Self::Q16 => "q16",
            Self::Q17 => "q17",
            Self::Q18 => "q18",
            Self::Q19 => "q19",
            Self::Q20 => "q20",
            Self::Q21 => "q21",
            Self::Q22 => "q22",
            Self::Q23 => "q23",
            Self::Q24 => "q24",
            Self::Q25 => "q25",
            Self::Q26 => "q26",
            Self::Q27 => "q27",
            Self::Q28 => "q28",
            Self::Q29 => "q29",
            Self::Q30 => "q30",
            Self::Q31 => "q31",
        }
    }
    
    /// Get the ABI name of the register (mostly for parameters and return values)
    pub fn abi_name(&self) -> Option<&'static str> {
        match self {
            Self::X0 => Some("arg1/return"),
            Self::X1 => Some("arg2"),
            Self::X2 => Some("arg3"),
            Self::X3 => Some("arg4"),
            Self::X4 => Some("arg5"),
            Self::X5 => Some("arg6"),
            Self::X6 => Some("arg7"),
            Self::X7 => Some("arg8"),
            Self::X8 => Some("indirect result"),
            Self::X9 | Self::X10 | Self::X11 | 
            Self::X12 | Self::X13 | Self::X14 | 
            Self::X15 => Some("caller saved"),
            Self::X16 => Some("IP0"),
            Self::X17 => Some("IP1"),
            Self::X18 => Some("platform register"),
            Self::X19 | Self::X20 | Self::X21 | 
            Self::X22 | Self::X23 | Self::X24 | 
            Self::X25 | Self::X26 | Self::X27 |
            Self::X28 => Some("callee saved"),
            Self::X29 => Some("frame pointer"),
            Self::X30 => Some("link register"),
            Self::Sp => Some("stack pointer"),
            Self::Pc => Some("program counter"),
            Self::Lr => Some("link register"),
            Self::Cpsr => Some("status register"),
            _ => None,
        }
    }
    
    /// Get the register group for display purposes
    pub fn group(&self) -> RegisterGroup {
        match self {
            Self::X0 | Self::X1 | Self::X2 | Self::X3 |
            Self::X4 | Self::X5 | Self::X6 | Self::X7 |
            Self::X8 | Self::X9 | Self::X10 | Self::X11 |
            Self::X12 | Self::X13 | Self::X14 | Self::X15 |
            Self::X16 | Self::X17 | Self::X18 | Self::X19 |
            Self::X20 | Self::X21 | Self::X22 | Self::X23 |
            Self::X24 | Self::X25 | Self::X26 | Self::X27 |
            Self::X28 | Self::X29 | Self::X30 => RegisterGroup::General,
            
            Self::Sp | Self::Pc | Self::Lr | Self::Cpsr => RegisterGroup::Special,
            
            Self::Q0 | Self::Q1 | Self::Q2 | Self::Q3 |
            Self::Q4 | Self::Q5 | Self::Q6 | Self::Q7 |
            Self::Q8 | Self::Q9 | Self::Q10 | Self::Q11 |
            Self::Q12 | Self::Q13 | Self::Q14 | Self::Q15 |
            Self::Q16 | Self::Q17 | Self::Q18 | Self::Q19 |
            Self::Q20 | Self::Q21 | Self::Q22 | Self::Q23 |
            Self::Q24 | Self::Q25 | Self::Q26 | Self::Q27 |
            Self::Q28 | Self::Q29 | Self::Q30 | Self::Q31 => RegisterGroup::Vector,
        }
    }
    
    /// Convert from index to register (for use with ARM thread state)
    pub fn from_arm64_index(idx: usize) -> Option<Self> {
        // Map from Apple's arm_thread_state64_t indexes to our Register enum
        match idx {
            0 => Some(Self::X0),
            1 => Some(Self::X1),
            2 => Some(Self::X2),
            3 => Some(Self::X3),
            4 => Some(Self::X4),
            5 => Some(Self::X5),
            6 => Some(Self::X6),
            7 => Some(Self::X7),
            8 => Some(Self::X8),
            9 => Some(Self::X9),
            10 => Some(Self::X10),
            11 => Some(Self::X11),
            12 => Some(Self::X12),
            13 => Some(Self::X13),
            14 => Some(Self::X14),
            15 => Some(Self::X15),
            16 => Some(Self::X16),
            17 => Some(Self::X17),
            18 => Some(Self::X18),
            19 => Some(Self::X19),
            20 => Some(Self::X20),
            21 => Some(Self::X21),
            22 => Some(Self::X22),
            23 => Some(Self::X23),
            24 => Some(Self::X24),
            25 => Some(Self::X25),
            26 => Some(Self::X26),
            27 => Some(Self::X27),
            28 => Some(Self::X28),
            29 => Some(Self::X29), // Frame pointer (FP)
            30 => Some(Self::X30), // Link register (LR)
            31 => Some(Self::Sp),  // Stack pointer (SP)
            32 => Some(Self::Pc),  // Program counter (PC)
            33 => Some(Self::Cpsr), // CPSR
            _ => None,
        }
    }
    
    /// Get the arm64 thread state index for this register
    pub fn to_arm64_index(self) -> Option<usize> {
        match self {
            Self::X0 => Some(0),
            Self::X1 => Some(1),
            Self::X2 => Some(2),
            Self::X3 => Some(3),
            Self::X4 => Some(4),
            Self::X5 => Some(5),
            Self::X6 => Some(6),
            Self::X7 => Some(7),
            Self::X8 => Some(8),
            Self::X9 => Some(9),
            Self::X10 => Some(10),
            Self::X11 => Some(11),
            Self::X12 => Some(12),
            Self::X13 => Some(13),
            Self::X14 => Some(14),
            Self::X15 => Some(15),
            Self::X16 => Some(16),
            Self::X17 => Some(17),
            Self::X18 => Some(18),
            Self::X19 => Some(19),
            Self::X20 => Some(20),
            Self::X21 => Some(21),
            Self::X22 => Some(22),
            Self::X23 => Some(23),
            Self::X24 => Some(24),
            Self::X25 => Some(25),
            Self::X26 => Some(26),
            Self::X27 => Some(27),
            Self::X28 => Some(28),
            Self::X29 => Some(29),
            Self::X30 => Some(30),
            Self::Sp => Some(31),
            Self::Pc => Some(32),
            Self::Lr => Some(33),
            Self::Cpsr => Some(34),
            _ => None, // SIMD registers use a different state type
        }
    }
    
    /// Get all general purpose registers
    pub fn general_purpose_registers() -> Vec<Self> {
        vec![
            Self::X0, Self::X1, Self::X2, Self::X3,
            Self::X4, Self::X5, Self::X6, Self::X7,
            Self::X8, Self::X9, Self::X10, Self::X11,
            Self::X12, Self::X13, Self::X14, Self::X15,
            Self::X16, Self::X17, Self::X18, Self::X19,
            Self::X20, Self::X21, Self::X22, Self::X23,
            Self::X24, Self::X25, Self::X26, Self::X27,
            Self::X28, Self::X29, Self::X30,
        ]
    }
    
    /// Get all special registers
    pub fn special_registers() -> Vec<Self> {
        vec![Self::Sp, Self::Pc, Self::Cpsr]
    }
    
    /// Get all SIMD registers
    pub fn simd_registers() -> Vec<Self> {
        vec![
            Self::Q0, Self::Q1, Self::Q2, Self::Q3,
            Self::Q4, Self::Q5, Self::Q6, Self::Q7,
            Self::Q8, Self::Q9, Self::Q10, Self::Q11,
            Self::Q12, Self::Q13, Self::Q14, Self::Q15,
            Self::Q16, Self::Q17, Self::Q18, Self::Q19,
            Self::Q20, Self::Q21, Self::Q22, Self::Q23,
            Self::Q24, Self::Q25, Self::Q26, Self::Q27,
            Self::Q28, Self::Q29, Self::Q30, Self::Q31,
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
            Self::General => write!(f, "General Purpose"),
            Self::Special => write!(f, "Special"),
            Self::Vector => write!(f, "Vector/SIMD"),
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
        self.get(Register::Sp)
    }
    
    /// Get the program counter value
    pub fn get_program_counter(&self) -> Option<u64> {
        self.get(Register::Pc)
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
