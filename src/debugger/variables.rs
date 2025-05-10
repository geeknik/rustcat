use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::fmt;

use anyhow::{Result, anyhow};
use log::debug;

use crate::debugger::symbols::SymbolTable;
use goblin::{elf, mach, Object};

/// Represents a variable's type
#[derive(Debug, Clone, PartialEq)]
pub enum VariableType {
    /// Integer types
    Integer(IntegerType),
    /// Floating point types
    Float(FloatType),
    /// Boolean type
    Boolean,
    /// Character type
    Char,
    /// String type
    String,
    /// Pointer type
    Pointer(Box<VariableType>),
    /// Array type
    Array(Box<VariableType>, usize),
    /// Structure type
    Struct(String),
    /// Enum type
    Enum(String),
    /// Unknown type
    Unknown,
}

/// Integer types with their sizes
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum IntegerType {
    /// 8-bit integer
    I8,
    /// 16-bit integer
    I16,
    /// 32-bit integer
    I32,
    /// 64-bit integer
    I64,
    /// 8-bit unsigned integer
    U8,
    /// 16-bit unsigned integer
    U16,
    /// 32-bit unsigned integer
    U32,
    /// 64-bit unsigned integer
    U64,
}

/// Floating point types with their sizes
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum FloatType {
    /// 32-bit float
    F32,
    /// 64-bit float
    F64,
}

impl fmt::Display for VariableType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VariableType::Integer(int_type) => match int_type {
                IntegerType::I8 => write!(f, "i8"),
                IntegerType::I16 => write!(f, "i16"),
                IntegerType::I32 => write!(f, "i32"),
                IntegerType::I64 => write!(f, "i64"),
                IntegerType::U8 => write!(f, "u8"),
                IntegerType::U16 => write!(f, "u16"),
                IntegerType::U32 => write!(f, "u32"),
                IntegerType::U64 => write!(f, "u64"),
            },
            VariableType::Float(float_type) => match float_type {
                FloatType::F32 => write!(f, "f32"),
                FloatType::F64 => write!(f, "f64"),
            },
            VariableType::Boolean => write!(f, "bool"),
            VariableType::Char => write!(f, "char"),
            VariableType::String => write!(f, "string"),
            VariableType::Pointer(pointed_type) => write!(f, "*{}", pointed_type),
            VariableType::Array(element_type, size) => write!(f, "{}[{}]", element_type, size),
            VariableType::Struct(name) => write!(f, "struct {}", name),
            VariableType::Enum(name) => write!(f, "enum {}", name),
            VariableType::Unknown => write!(f, "unknown"),
        }
    }
}

/// Represents a variable's value
#[derive(Debug, Clone)]
pub enum VariableValue {
    /// Integer value
    Integer(i64),
    /// Unsigned integer value
    UInteger(u64),
    /// Floating point value
    Float(f64),
    /// Boolean value
    Boolean(bool),
    /// Character value
    Char(char),
    /// String value
    String(String),
    /// Pointer value (memory address)
    Pointer(u64),
    /// Array value (values of elements)
    Array(Vec<VariableValue>),
    /// Struct value (field names and values)
    Struct(HashMap<String, VariableValue>),
    /// Enum value (variant name and associated value if any)
    Enum(String, Option<Box<VariableValue>>),
    /// Raw bytes (for unknown types)
    RawBytes(Vec<u8>),
    /// Out of scope or unavailable
    Unavailable,
}

impl fmt::Display for VariableValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VariableValue::Integer(value) => write!(f, "{}", value),
            VariableValue::UInteger(value) => write!(f, "{}", value),
            VariableValue::Float(value) => write!(f, "{}", value),
            VariableValue::Boolean(value) => write!(f, "{}", value),
            VariableValue::Char(value) => write!(f, "'{}'", value),
            VariableValue::String(value) => write!(f, "\"{}\"", value),
            VariableValue::Pointer(addr) => write!(f, "0x{:x}", addr),
            VariableValue::Array(elements) => {
                write!(f, "[")?;
                for (i, element) in elements.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{}", element)?;
                }
                write!(f, "]")
            }
            VariableValue::Struct(fields) => {
                write!(f, "{{ ")?;
                let mut first = true;
                for (name, value) in fields {
                    if !first {
                        write!(f, ", ")?;
                    }
                    write!(f, "{}: {}", name, value)?;
                    first = false;
                }
                write!(f, " }}")
            }
            VariableValue::Enum(variant, value) => {
                write!(f, "{}",  variant)?;
                if let Some(val) = value {
                    write!(f, "({})", val)?;
                }
                Ok(())
            }
            VariableValue::RawBytes(bytes) => {
                write!(f, "bytes[")?;
                for (i, byte) in bytes.iter().enumerate() {
                    if i > 0 {
                        write!(f, " ")?;
                    }
                    write!(f, "{:02x}", byte)?;
                }
                write!(f, "]")
            }
            VariableValue::Unavailable => write!(f, "<unavailable>"),
        }
    }
}

/// Scope of a variable
#[derive(Debug, Clone, PartialEq)]
pub enum VariableScope {
    /// Global variable
    Global,
    /// Local variable
    Local,
    /// Instance variable (member of a class)
    Instance,
    /// Static variable
    Static,
    /// Register-based variable (optimization or argument)
    Register,
}

impl fmt::Display for VariableScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VariableScope::Global => write!(f, "global"),
            VariableScope::Local => write!(f, "local"),
            VariableScope::Instance => write!(f, "instance"),
            VariableScope::Static => write!(f, "static"),
            VariableScope::Register => write!(f, "register"),
        }
    }
}

/// Represents a variable in the debugged program
#[derive(Debug, Clone)]
pub struct Variable {
    /// Name of the variable
    name: String,
    /// Type of the variable
    var_type: VariableType,
    /// Current value of the variable
    value: VariableValue,
    /// Memory location of the variable (if stored in memory)
    address: Option<u64>,
    /// Stack frame index this variable belongs to
    frame_index: Option<usize>,
    /// Register the variable is stored in (if any)
    register: Option<String>,
    /// Whether the variable has changed since the last stop
    changed: bool,
    /// Scope of the variable
    scope: VariableScope,
    /// Source file where the variable is declared
    source_file: Option<String>,
    /// Line number where the variable is declared
    line_number: Option<u32>,
}

impl Variable {
    /// Create a new variable
    pub fn new(name: String, var_type: VariableType, value: VariableValue, scope: VariableScope) -> Self {
        Self {
            name,
            var_type,
            value,
            address: None,
            frame_index: None,
            register: None,
            changed: false,
            scope,
            source_file: None,
            line_number: None,
        }
    }

    /// Get the name of the variable
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get the type of the variable
    pub fn var_type(&self) -> &VariableType {
        &self.var_type
    }

    /// Get the value of the variable
    pub fn value(&self) -> &VariableValue {
        &self.value
    }

    /// Set the value of the variable
    pub fn set_value(&mut self, value: VariableValue) {
        self.changed = true;
        self.value = value;
    }

    /// Get the memory address of the variable
    pub fn address(&self) -> Option<u64> {
        self.address
    }

    /// Set the memory address of the variable
    pub fn set_address(&mut self, address: u64) {
        self.address = Some(address);
    }

    /// Get the stack frame index this variable belongs to
    pub fn frame_index(&self) -> Option<usize> {
        self.frame_index
    }

    /// Set the stack frame index
    pub fn set_frame_index(&mut self, frame_index: usize) {
        self.frame_index = Some(frame_index);
    }

    /// Get the register this variable is stored in
    pub fn register(&self) -> Option<&str> {
        self.register.as_deref()
    }

    /// Set the register this variable is stored in
    pub fn set_register(&mut self, register: String) {
        self.register = Some(register);
    }

    /// Check if the variable has changed since the last stop
    pub fn has_changed(&self) -> bool {
        self.changed
    }

    /// Mark the variable as unchanged
    pub fn mark_unchanged(&mut self) {
        self.changed = false;
    }

    /// Get the scope of the variable
    pub fn scope(&self) -> &VariableScope {
        &self.scope
    }

    /// Set source location information
    pub fn set_source_location(&mut self, file: String, line: u32) {
        self.source_file = Some(file);
        self.line_number = Some(line);
    }

    /// Get source file
    pub fn source_file(&self) -> Option<&str> {
        self.source_file.as_deref()
    }

    /// Get line number
    pub fn line_number(&self) -> Option<u32> {
        self.line_number
    }

    /// Format the variable for display
    pub fn format(&self) -> String {
        let mut result = format!("{}: {} = {}", self.name, self.var_type, self.value);
        
        if self.has_changed() {
            result.push_str(" (changed)");
        }
        
        if let Some(addr) = self.address {
            result.push_str(&format!(" @ 0x{:x}", addr));
        } else if let Some(reg) = &self.register {
            result.push_str(&format!(" (in {})", reg));
        }
        
        result
    }
}

/// Manager for tracking and inspecting variables
#[derive(Default)]
pub struct VariableManager {
    /// All known variables
    variables: HashMap<String, Variable>,
    /// Symbol table reference for looking up symbol information
    symbol_table: Option<Arc<Mutex<SymbolTable>>>,
}

impl VariableManager {
    /// Create a new variable manager
    pub fn new() -> Self {
        Self {
            variables: HashMap::new(),
            symbol_table: None,
        }
    }

    /// Set the symbol table reference
    pub fn set_symbol_table(&mut self, symbol_table: Arc<Mutex<SymbolTable>>) {
        self.symbol_table = Some(symbol_table);
    }

    /// Add a new variable
    pub fn add_variable(&mut self, variable: Variable) {
        self.variables.insert(variable.name().to_string(), variable);
    }

    /// Update a variable's value
    pub fn update_variable(&mut self, name: &str, value: VariableValue) -> Result<()> {
        if let Some(variable) = self.variables.get_mut(name) {
            variable.set_value(value);
            Ok(())
        } else {
            Err(anyhow!("Variable '{}' not found", name))
        }
    }

    /// Get a variable by name
    pub fn get_variable(&self, name: &str) -> Option<&Variable> {
        self.variables.get(name)
    }

    /// Get a mutable reference to a variable by name
    pub fn get_variable_mut(&mut self, name: &str) -> Option<&mut Variable> {
        self.variables.get_mut(name)
    }

    /// Remove a variable
    pub fn remove_variable(&mut self, name: &str) -> Option<Variable> {
        self.variables.remove(name)
    }

    /// Get all variables
    pub fn get_all_variables(&self) -> Vec<&Variable> {
        self.variables.values().collect()
    }

    /// Get all variables of a specific scope
    pub fn get_variables_by_scope(&self, scope: VariableScope) -> Vec<&Variable> {
        self.variables.values()
            .filter(|v| v.scope() == &scope)
            .collect()
    }

    /// Get all variables in a specific stack frame
    pub fn get_variables_by_frame(&self, frame_index: usize) -> Vec<&Variable> {
        self.variables.values()
            .filter(|v| v.frame_index() == Some(frame_index))
            .collect()
    }

    /// Clear all variables
    pub fn clear(&mut self) {
        self.variables.clear();
    }

    /// Clear variables of a specific scope
    pub fn clear_scope(&mut self, scope: VariableScope) {
        self.variables.retain(|_, v| v.scope() != &scope);
    }

    /// Clear variables from a specific frame
    pub fn clear_frame(&mut self, frame_index: usize) {
        self.variables.retain(|_, v| v.frame_index() != Some(frame_index));
    }

    /// Mark all variables as unchanged
    pub fn mark_all_unchanged(&mut self) {
        for var in self.variables.values_mut() {
            var.mark_unchanged();
        }
    }

    /// Update local variables based on the current stack frame
    pub fn update_locals(&mut self, _pid: i32, frame_index: usize) -> Result<()> {
        // In a real implementation, this would:
        // 1. Use DWARF debug info to find local variables in this stack frame
        // 2. Read their values from memory or registers
        // 3. Add or update the variables in the manager
        
        // For now, we'll just log that we're updating locals
        debug!("Updating local variables for frame {}", frame_index);
        Ok(())
    }

    /// Parse a variable expression and return the variable value
    pub fn evaluate_expression(&mut self, expression: &str, pid: i32) -> Result<VariableValue> {
        // Trim whitespace
        let expression = expression.trim();
        
        // Check empty expression
        if expression.is_empty() {
            return Err(anyhow!("Empty expression"));
        }
        
        // Simple expression evaluation - check if it's a variable name
        if let Some(var) = self.get_variable(expression) {
            return Ok(var.value().clone());
        }
        
        // Try to parse numeric literals
        if let Ok(value) = expression.parse::<i64>() {
            return Ok(VariableValue::Integer(value));
        }
        
        if expression.starts_with("0x") || expression.starts_with("0X") {
            if let Ok(value) = u64::from_str_radix(&expression[2..], 16) {
                return Ok(VariableValue::UInteger(value));
            }
        }
        
        // Try to parse string literals
        if expression.starts_with('"') && expression.ends_with('"') && expression.len() >= 2 {
            return Ok(VariableValue::String(expression[1..expression.len()-1].to_string()));
        }
        
        // Try to parse boolean literals
        if expression == "true" {
            return Ok(VariableValue::Boolean(true));
        } else if expression == "false" {
            return Ok(VariableValue::Boolean(false));
        }
        
        // Handle dereferencing pointers: *expr
        if expression.starts_with('*') && expression.len() > 1 {
            // Evaluate the inner expression to get the address
            let inner_expr = &expression[1..];
            let inner_value = self.evaluate_expression(inner_expr, pid)?;
            
            // Convert the value to an address
            let _address = match inner_value {
                VariableValue::UInteger(addr) => addr,
                VariableValue::Integer(addr) if addr >= 0 => addr as u64,
                VariableValue::Pointer(addr) => addr,
                _ => return Err(anyhow!("Cannot dereference non-pointer value: {:?}", inner_value)),
            };
            
            // TODO: Use platform to read memory at address
            // For now, return a placeholder
            return Ok(VariableValue::UInteger(0xDEADBEEF));
        }
        
        // Handle address-of operator: &var
        if expression.starts_with('&') && expression.len() > 1 {
            let var_name = &expression[1..];
            if let Some(var) = self.get_variable(var_name) {
                if let Some(addr) = var.address() {
                    return Ok(VariableValue::Pointer(addr));
                } else {
                    return Err(anyhow!("Variable '{}' is not stored in memory", var_name));
                }
            } else {
                return Err(anyhow!("Variable '{}' not found", var_name));
            }
        }
        
        // Handle member access: expr.member
        if let Some(dot_pos) = expression.find('.') {
            let struct_expr = &expression[..dot_pos];
            let member_name = &expression[dot_pos+1..];
            
            // Evaluate the struct expression
            let struct_value = self.evaluate_expression(struct_expr, pid)?;
            
            // Try to access the member
            match struct_value {
                VariableValue::Struct(fields) => {
                    if let Some(member_value) = fields.get(member_name) {
                        return Ok(member_value.clone());
                    } else {
                        return Err(anyhow!("Member '{}' not found in struct", member_name));
                    }
                },
                _ => return Err(anyhow!("Cannot access member of non-struct value")),
            }
        }
        
        // Handle array indexing: array[index]
        if let Some(bracket_pos) = expression.find('[') {
            if !expression.ends_with(']') {
                return Err(anyhow!("Mismatched brackets in array access"));
            }
            
            let array_expr = &expression[..bracket_pos];
            let index_expr = &expression[bracket_pos+1..expression.len()-1];
            
            // Evaluate the array expression
            let array_value = self.evaluate_expression(array_expr, pid)?;
            
            // Evaluate the index expression
            let index_value = self.evaluate_expression(index_expr, pid)?;
            
            // Get the index as a number
            let index = match index_value {
                VariableValue::Integer(i) => {
                    if i < 0 {
                        return Err(anyhow!("Negative array index: {}", i));
                    }
                    i as usize
                },
                VariableValue::UInteger(i) => i as usize,
                _ => return Err(anyhow!("Array index must be an integer")),
            };
            
            // Try to access the array element
            match array_value {
                VariableValue::Array(elements) => {
                    if index < elements.len() {
                        return Ok(elements[index].clone());
                    } else {
                        return Err(anyhow!("Array index out of bounds: {} (size {})", index, elements.len()));
                    }
                },
                _ => return Err(anyhow!("Cannot index into non-array value")),
            }
        }
        
        // Handle register access: $reg
        if expression.starts_with('$') && expression.len() > 1 {
            let reg_name = &expression[1..];
            
            // For demonstration purposes, create some fake register values
            let registers = HashMap::from([
                ("pc", 0x1000u64),
                ("sp", 0x7FFF_FFFF_FFFFu64),
                ("x0", 42u64),
                ("x1", 100u64),
            ]);
            
            if let Some(&value) = registers.get(reg_name) {
                return Ok(VariableValue::UInteger(value));
            } else {
                return Err(anyhow!("Unknown register: ${}", reg_name));
            }
            
            // TODO: Access actual registers from debugger
        }
        
        // Handle memory access: *(type)addr
        if expression.starts_with("*(") {
            // Parse the type and address
            // Expected format: *(type)addr
            let type_end = expression.find(')');
            if let Some(pos) = type_end {
                let type_name = &expression[2..pos];
                let addr_expr = &expression[pos+1..];
                
                // Evaluate the address expression
                let addr_value = self.evaluate_expression(addr_expr, pid)?;
                
                // Convert to address
                let _addr = match addr_value {
                    VariableValue::UInteger(a) => a,
                    VariableValue::Integer(a) if a >= 0 => a as u64,
                    VariableValue::Pointer(a) => a,
                    _ => return Err(anyhow!("Invalid address in memory access: {:?}", addr_value)),
                };
                
                // TODO: Read memory at address with appropriate type
                // For now, return dummy values based on type
                match type_name {
                    "int" | "i32" => return Ok(VariableValue::Integer(0x12345678)),
                    "long" | "i64" => return Ok(VariableValue::Integer(0x1234567890ABCDEF)),
                    "float" | "f32" => return Ok(VariableValue::Float(std::f64::consts::PI)),
                    "double" | "f64" => return Ok(VariableValue::Float(std::f64::consts::E)),
                    "char" => return Ok(VariableValue::Char('A')),
                    "bool" => return Ok(VariableValue::Boolean(true)),
                    _ => return Err(anyhow!("Unsupported type in memory access: {}", type_name)),
                }
            }
        }
        
        // Handle basic arithmetic operations
        for (pos, c) in expression.char_indices().rev() {
            if c == '+' || c == '-' || c == '*' || c == '/' || c == '%' {
                // Make sure it's not part of a more complex expression
                let preceding = &expression[..pos];
                
                // Skip if the operator is within parentheses
                let open_count = preceding.chars().filter(|&c| c == '(').count();
                let close_count = preceding.chars().filter(|&c| c == ')').count();
                
                if open_count != close_count {
                    continue;
                }
                
                // Extract left and right expressions
                let left_expr = expression[..pos].trim();
                let right_expr = expression[pos+1..].trim();
                
                // Evaluate both sides
                let left_result = self.evaluate_expression(left_expr, pid);
                let right_result = self.evaluate_expression(right_expr, pid);
                
                // Handle evaluation errors
                if let Err(e) = &left_result {
                    return Err(anyhow!("Error evaluating left operand: {}", e));
                }
                if let Err(e) = &right_result {
                    return Err(anyhow!("Error evaluating right operand: {}", e));
                }
                
                let left_value = left_result.unwrap();
                let right_value = right_result.unwrap();
                
                // Perform operations based on the types
                return match (left_value, right_value) {
                    (VariableValue::Integer(a), VariableValue::Integer(b)) => {
                        match c {
                            '+' => Ok(VariableValue::Integer(a + b)),
                            '-' => Ok(VariableValue::Integer(a - b)),
                            '*' => Ok(VariableValue::Integer(a * b)),
                            '/' => {
                                if b == 0 {
                                    Err(anyhow!("Division by zero"))
                                } else {
                                    Ok(VariableValue::Integer(a / b))
                                }
                            },
                            '%' => {
                                if b == 0 {
                                    Err(anyhow!("Modulo by zero"))
                                } else {
                                    Ok(VariableValue::Integer(a % b))
                                }
                            },
                            _ => Err(anyhow!("Unsupported operation '{}' for integer types", c)),
                        }
                    },
                    (VariableValue::UInteger(a), VariableValue::UInteger(b)) => {
                        match c {
                            '+' => Ok(VariableValue::UInteger(a + b)),
                            '-' => Ok(VariableValue::UInteger(a.saturating_sub(b))),
                            '*' => Ok(VariableValue::UInteger(a * b)),
                            '/' => {
                                if b == 0 {
                                    Err(anyhow!("Division by zero"))
                                } else {
                                    Ok(VariableValue::UInteger(a / b))
                                }
                            },
                            '%' => {
                                if b == 0 {
                                    Err(anyhow!("Modulo by zero"))
                                } else {
                                    Ok(VariableValue::UInteger(a % b))
                                }
                            },
                            _ => Err(anyhow!("Unsupported operation '{}' for unsigned integer types", c)),
                        }
                    },
                    (VariableValue::Float(a), VariableValue::Float(b)) => {
                        match c {
                            '+' => Ok(VariableValue::Float(a + b)),
                            '-' => Ok(VariableValue::Float(a - b)),
                            '*' => Ok(VariableValue::Float(a * b)),
                            '/' => {
                                if b == 0.0 {
                                    Err(anyhow!("Division by zero"))
                                } else {
                                    Ok(VariableValue::Float(a / b))
                                }
                            },
                            '%' => Err(anyhow!("Modulo not supported for floating-point values")),
                            _ => Err(anyhow!("Unsupported operation '{}' for floating-point types", c)),
                        }
                    },
                    // Handle mixed type operations with appropriate conversions
                    (VariableValue::Integer(a), VariableValue::UInteger(b)) => {
                        match c {
                            '+' => {
                                if a >= 0 {
                                    Ok(VariableValue::UInteger(a as u64 + b))
                                } else if b > a.unsigned_abs() {
                                    Ok(VariableValue::UInteger(b - a.unsigned_abs()))
                                } else {
                                    Ok(VariableValue::Integer(a + b as i64))
                                }
                            },
                            '-' => Ok(VariableValue::Integer(a - b as i64)),
                            '*' => Ok(VariableValue::Integer(a * b as i64)),
                            '/' => {
                                if b == 0 {
                                    Err(anyhow!("Division by zero"))
                                } else {
                                    Ok(VariableValue::Integer(a / b as i64))
                                }
                            },
                            '%' => {
                                if b == 0 {
                                    Err(anyhow!("Modulo by zero"))
                                } else {
                                    Ok(VariableValue::Integer(a % b as i64))
                                }
                            },
                            _ => Err(anyhow!("Unsupported operation '{}' for mixed types", c)),
                        }
                    },
                    // Add other combinations as needed
                    (left, right) => Err(anyhow!("Incompatible types for operation '{}': {:?} and {:?}", 
                                         c, left, right)),
                };
            }
        }
        
        // Handle parenthesized expressions
        if expression.starts_with('(') && expression.ends_with(')') && expression.len() >= 2 {
            let inner_expr = &expression[1..expression.len()-1];
            return self.evaluate_expression(inner_expr, pid);
        }
        
        // If we got here, we couldn't evaluate the expression
        Err(anyhow!("Could not evaluate expression: {}", expression))
    }

    /// Look up variable information from debug symbols
    fn lookup_variable_info(&self, name: &str, _address: u64) -> Option<(VariableType, String)> {
        // In a real implementation, this would:
        // 1. Use DWARF debug info to find information about the variable
        // 2. Return the type and other metadata
        
        // For now, just return a placeholder based on the name
        let var_type = if name.starts_with('i') {
            VariableType::Integer(IntegerType::I32)
        } else if name.starts_with('f') {
            VariableType::Float(FloatType::F32)
        } else if name.starts_with('b') {
            VariableType::Boolean
        } else if name.starts_with('c') {
            VariableType::Char
        } else if name.starts_with('s') {
            VariableType::String
        } else if name.starts_with('p') {
            VariableType::Pointer(Box::new(VariableType::Unknown))
        } else {
            VariableType::Unknown
        };
        
        Some((var_type, "Unknown source location".to_string()))
    }
}

/// Helper functions for DWARF type information
mod dwarf_helpers {
    use super::*;
    
    /// Convert a DWARF base type to a VariableType
    pub fn dwarf_base_type_to_variable_type(encoding: u64, byte_size: u64) -> VariableType {
        // DWARF encodings (from DWARF v4 spec)
        const DW_ATE_ADDRESS: u64 = 0x01;
        const DW_ATE_BOOLEAN: u64 = 0x02;
        const DW_ATE_COMPLEX_FLOAT: u64 = 0x03;
        const DW_ATE_FLOAT: u64 = 0x04;
        const DW_ATE_SIGNED: u64 = 0x05;
        const DW_ATE_SIGNED_CHAR: u64 = 0x06;
        const DW_ATE_UNSIGNED: u64 = 0x07;
        const DW_ATE_UNSIGNED_CHAR: u64 = 0x08;
        
        match encoding {
            DW_ATE_ADDRESS => VariableType::Pointer(Box::new(VariableType::Unknown)),
            DW_ATE_BOOLEAN => VariableType::Boolean,
            DW_ATE_FLOAT => match byte_size {
                4 => VariableType::Float(FloatType::F32),
                8 => VariableType::Float(FloatType::F64),
                _ => VariableType::Unknown,
            },
            DW_ATE_SIGNED => match byte_size {
                1 => VariableType::Integer(IntegerType::I8),
                2 => VariableType::Integer(IntegerType::I16),
                4 => VariableType::Integer(IntegerType::I32),
                8 => VariableType::Integer(IntegerType::I64),
                _ => VariableType::Unknown,
            },
            DW_ATE_SIGNED_CHAR => VariableType::Char,
            DW_ATE_UNSIGNED => match byte_size {
                1 => VariableType::Integer(IntegerType::U8),
                2 => VariableType::Integer(IntegerType::U16),
                4 => VariableType::Integer(IntegerType::U32),
                8 => VariableType::Integer(IntegerType::U64),
                _ => VariableType::Unknown,
            },
            DW_ATE_UNSIGNED_CHAR => VariableType::Char,
            _ => VariableType::Unknown,
        }
    }
} 