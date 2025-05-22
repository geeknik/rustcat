# RUSTCAT 🦀🐱

**A MacOS-Only, Rust-Based, Fast-as-Hell Native Debugger**

<p align="center">
  <img src="https://img.shields.io/badge/rust-nightly-orange.svg" alt="Rust Version: Nightly">
  <img src="https://img.shields.io/badge/platform-macOS%20ARM64-blue.svg" alt="Platform: macOS ARM64">
  <img src="https://img.shields.io/badge/status-alpha-red.svg" alt="Status: Alpha">
  <img src="https://img.shields.io/badge/license-MIT-green.svg" alt="License: MIT">
</p>

## What is RUSTCAT?

RUSTCAT is not a gdb wrapper. It is not a hacked lldb clone. It is a from-scratch debugger built for speed, terminal warriors, and modern machines. ClickHouse-sized workloads? Handled. Real-time updates? You bet. UI freezes? Not in this house.

This is the debugger macOS should ship with, but doesn't. So we did it ourselves.

![RUSTCAT Screenshot](docs/screenshots/rustcat_tui.png)

## Features

- ⚡ **Blazing Fast**: Zero-wait responsiveness for all interactive commands
- 🧠 **Smart Parsing**: Robust symbol and DWARF debug info handling
- 🖥️ **Beautiful TUI**: Terminal-based UI with vi-like navigation
- 🔍 **Deep Inspection**: Memory, registers, threads, and more at your fingertips
- 🧵 **Multi-threaded**: Background operations for heavy lifting tasks

## Current Status

- ✅ Basic TUI with four-panel layout
- ✅ Symbol loading
- ✅ DWARF debug info parsing
- ✅ Mach-O format support
- 🚧 Breakpoints and stepping (WIP)
- 🚧 Memory inspection (WIP)
- 🚧 Registers view (WIP)

## Installation

### Prerequisites

- macOS Ventura or later on Apple Silicon (M1/M2/M3)
- Rust nightly toolchain

### Build from Source

```bash
# Clone the repository
git clone https://github.com/geeknik/rustcat.git
cd rustcat

# Build with cargo
cargo build --release

# Install to your path (optional)
cargo install --path .
```

## Quick Start

```bash
# Debug a binary
rustcat /path/to/binary

# With arguments
rustcat /path/to/binary arg1 arg2
```

## Usage

Once in the TUI:

- **Navigation**: `h` (left), `l` (right) to switch between panes
- **Quit**: `q` to exit
- **Commands** (coming soon):
  - `b <address/function>` - Set breakpoint
  - `c` - Continue
  - `s` - Step instruction
  - `r` - Run/restart
  - `:` - Command mode

## Under the Hood

RUSTCAT is built from scratch with:

- **Core Engine**: Custom debug engine using Mach kernel APIs
- **Symbol Parsing**: Native Mach-O and DWARF parsing
- **TUI**: Built with ratatui and crossterm for a beautiful terminal interface
- **Architecture**: Modular design with clear separation of concerns

## Roadmap

- **v0.1**: Basic debugging features, symbol loading, TUI
- **v0.2**: Breakpoints, stepping, memory viewing
- **v0.3**: Advanced features like conditional breakpoints, watchpoints
- **v0.4**: Performance optimizations and larger binary support

## Contributing

Contributions are welcome! Please check out our [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgements

- The Rust community for amazing libraries
- macOS internals documentation and research papers
- Contributors and testers

---

*You shouldn't wait to debug your code.  
You shouldn't fight your tools.  
You shouldn't be forced to read Apple crash dumps to learn assembly.*

*RUSTCAT is the debugger Mac deserves. Clean. Deterministic. Free.*
