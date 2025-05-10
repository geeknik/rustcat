# 🧠 RUSTCAT

A MacOS-Only, Rust-Based, Fast-as-Hell Native Debugger

## TL;DR

You're staring down the future of native code debugging on macOS ARM64. RUSTCAT is not a gdb wrapper. It is not a hacked lldb clone. It is a from-scratch debugger built for speed, terminal warriors, and modern machines. ClickHouse-sized workloads? Handled. Real-time updates? You bet. UI freezes? Not in this house.

This is the debugger macOS should ship with, but doesn't. So we did it ourselves.

## 🧩 Core Features

- **MacOS ARM64 Only**: Built specifically for Apple Silicon
- **⚡ Fast**: Zero-wait responsiveness for all interactive commands
- **👁 TUI**: Terminal UI with keyboard-driven interface
- **🔬 From-Scratch**: Custom-built debug engine (no LLDB or GDB)
- **🧵 Multithreaded**: Background worker pools for heavy operations
- **🔧 Low-level**: Uses macOS-specific APIs for ptrace, mach threads, etc.
- **🔄 Dynamic Symbols**: C++ name demangling and advanced symbol resolution
- **📊 Rich Memory Views**: Inspect memory as hex, ASCII, integers, floats, etc.
- **🧵 Advanced Breakpoints**: Conditions, ignore counts, log messages
- **📊 Thread Management**: Track thread states, build call stacks, manage thread-specific breakpoints

## 🚀 Performance

- **Instantaneous** (sub-10ms) UI redraws, navigation, breakpoint setting
- **Efficient** multi-threaded parsing of DWARF/ELF/Mach-O
- **Handles** large binaries (2.5GB+ tested)

## 🖥 Interface

Terminal-Only UI with vi-like keyboard shortcuts:
- Split Panels: Code view | Stack trace | Memory | Threads
- Dynamic Layout: Resizable panes, toggleable regions
- Keyboard-Driven: g (go), s (step), f (stack frame), / (search), : (command mode)

## Current Status

RUSTCAT is currently in alpha development. The core debugger engine is functional, supporting breakpoints, memory inspection, and thread management. The TUI interface is operational with multiple views:

- Code view for source code examination
- Memory view with hex, ASCII, and various numeric formats
- Thread inspection showing thread states and locations
- Call stack view with source location information
- Command input with history and tab-completion

## 🛠 Running the Project

```bash
# Clone the repository
git clone https://github.com/geeknik/rustcat.git
cd rustcat

# Build the project
cargo build

# Run with a target program
cargo run -- /path/to/program

# Or use the provided run script
./run.command /path/to/program
```

## 📋 Requirements

- macOS Ventura or later
- Apple Silicon M1/M2/M3 (ARM64)
- Rust and Cargo installed

## Keyboard Controls

- `q`: Quit
- `g`: Run/continue program
- `b`: Set breakpoint
- `s`: Step instruction
- `n`: Step over
- `c`: Switch to code view
- `m`: Switch to memory view
- `r`: Switch to registers view
- `w`: Switch to stack view (call stack)
- `t`: Switch to threads view
- `:`: Switch to command mode
- `Tab`: Switch between UI panels

## Command Mode

Enter command mode with `:` and type commands like:
- `break main` - Set breakpoint at main function
- `break 0x1000` - Set breakpoint at memory address
- `continue` - Continue execution
- `step` - Step into
- `next` - Step over
- `memory 0x1000 100` - View 100 bytes of memory at address 0x1000
- `help` - Show help

## 🧬 Philosophy

You shouldn't wait to debug your code.
You shouldn't fight your tools.
You shouldn't be forced to read Apple crash dumps to learn assembly.

Rustcat is the debugger Mac deserves. Clean. Deterministic. Free.
No more syscalls in the dark. Let's light this up.

## 🔮 Roadmap

- [x] Project initialization
- [x] TUI interface
- [x] Core debugger engine
- [x] Breakpoint management
  - [x] Basic breakpoints
  - [x] Conditional breakpoints
  - [x] Logging breakpoints
  - [x] Hit counts and ignore counts
- [x] Symbol resolution
  - [x] ELF, Mach-O, and PE support
  - [x] C++ name demangling
  - [x] Symbol type classification
- [x] Memory inspection
  - [x] Hex, ASCII, UTF-8 views
  - [x] Integer/Floating point views
  - [x] Memory region tracking
- [x] Thread handling
  - [x] Thread state tracking
  - [x] Thread-specific breakpoints
  - [x] Call stack building
- [x] DWARF parsing
  - [x] Source line mapping
  - [x] Function info
  - [x] Source code viewing
- [ ] Full ARM64 register support
- [ ] Disassembly view
- [ ] Function call tracing
- [ ] Variable inspection
- [ ] Expression evaluation
- [ ] Watchpoints
- [ ] Full documentation

## 📄 License

MIT License
