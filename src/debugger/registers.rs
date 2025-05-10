use std::collections::HashMap;

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
    
    // FP/SIMD registers
    Q0, Q1, Q2, Q3, Q4, Q5, Q6, Q7,
    Q8, Q9, Q10, Q11, Q12, Q13, Q14, Q15,
    Q16, Q17, Q18, Q19, Q20, Q21, Q22, Q23,
    Q24, Q25, Q26, Q27, Q28, Q29, Q30, Q31,
}

/// Register values for a thread
pub struct Registers {
    /// Register values
    values: HashMap<Register, u64>,
}

impl Registers {
    /// Create a new empty register set
    pub fn new() -> Self {
        Self {
            values: HashMap::new(),
        }
    }
    
    /// Set a register value
    pub fn set(&mut self, reg: Register, value: u64) {
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
            self.values.insert(reg, value);
        }
    }
    
    /// Clear all register values
    pub fn clear(&mut self) {
        self.values.clear();
    }
}

impl Default for Registers {
    fn default() -> Self {
        Self::new()
    }
}
