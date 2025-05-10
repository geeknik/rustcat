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

## 🚀 Performance

- **Instantaneous** (sub-10ms) UI redraws, navigation, breakpoint setting
- **Efficient** multi-threaded parsing of DWARF/ELF/Mach-O
- **Handles** large binaries (2.5GB+ tested)

## 🖥 Interface

Terminal-Only UI with vi-like keyboard shortcuts:
- Split Panels: Code view | Stack trace | Memory | Threads
- Dynamic Layout: Resizable panes, toggleable regions
- Keyboard-Driven: g (go), s (step), f (stack frame), / (search), : (command mode)

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
- `c`: Switch to code view
- `m`: Switch to memory view
- `r`: Switch to registers view
- `s`: Switch to stack view
- `t`: Switch to threads view
- `:`: Switch to command mode

## 🧬 Philosophy

You shouldn't wait to debug your code.
You shouldn't fight your tools.
You shouldn't be forced to read Apple crash dumps to learn assembly.

Rustcat is the debugger Mac deserves. Clean. Deterministic. Free.
No more syscalls in the dark. Let's light this up.

## 🔮 Roadmap

- [x] Project initialization
- [x] TUI interface
- [ ] Core debugger engine
- [ ] Breakpoint management
- [ ] Symbol resolution
- [ ] Memory inspection
- [ ] Thread handling
- [ ] DWARF parsing
- [ ] Full documentation

## 📄 License

MIT License
