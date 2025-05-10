🧠 DESIGN.md – RUSTCAT

A MacOS-Only, Rust-Based, Fast-as-Hell Native Debugger

TL;DR:

You're staring down the future of native code debugging on macOS ARM64. RUSTCAT is not a gdb wrapper. It is not a hacked lldb clone. It is a from-scratch debugger built for speed, terminal warriors, and modern machines. ClickHouse-sized workloads? Handled. Real-time updates? You bet. UI freezes? Not in this house.

This is the debugger macOS should ship with, but doesn't. So we did it ourselves.

⸻

🧩 Core Objectives

✦ Platform Specificity
	•	OS: macOS Ventura+ (ARM64 only, Apple Silicon)
	•	Arch: 64-bit only
	•	Focus: Native code (e.g., C, C++, Rust)
	•	Excluded: Python, Java, .NET, WebAssembly, etc.

✦ Design Philosophy
	•	⚡ Fast: Zero-wait responsiveness for all interactive commands
	•	👁 TUI: Terminal UI with ncurses-style layout (but we use tui-rs or equivalent)
	•	🔬 From-Scratch: Custom-built debug engine. No LLDB or GDB behind the curtain.
	•	🧵 Multithreaded: Heavy operations like DWARF parsing, symbol lookup, or memory map generation run on background worker pools
	•	🔧 Low-level: Uses macOS-specific APIs for ptrace, mach threads, code-signing validation, etc.

⸻

📦 High-Level Architecture

+-------------------------------+
|           Rustcat            |
+-------------------------------+
|    Frontend (TUI Layer)      |
| ──────────────────────────── |
| Command Handler / REPL-like  |
| Syntax Highlighting / Views  |
+-------------------------------+
|      Debugger Core Engine     |
| ──────────────────────────── |
| Breakpoints / Stepping Logic |
| Memory & Register Inspector  |
| Symbol Resolver / DWARF      |
| Threads & Context Switcher   |
+-------------------------------+
|         Platform Layer        |
| ──────────────────────────── |
| Ptrace / Mach APIs           |
| Task / Thread Introspection  |
| M1 Register Map Support      |
+-------------------------------+
|           OS / Kernel         |
+-------------------------------+


⸻

🖥 Interface

Terminal-Only UI

Built with ratatui or crossterm. Designed to be mouse-free, vi-like:
	•	Split Panels: Code view | Stack trace | Memory | Threads
	•	Dynamic Layout: Resizable panes, toggleable regions
	•	Keyboard-Driven: g (go), s (step), f (stack frame), / (search), : (command mode)

TUI Flow Example

$ rustcat ./clickhouse
> Loading symbols… ██████▌ 91%
> Breakpoint set @ main()
> run
> [PID 12345] ⬤ hit breakpoint at main() +0x14


⸻

🚀 Performance Goals

Instantaneous (sub-10ms expected)
	•	UI redraws, navigation, switching panes
	•	Setting breakpoints (pre-loaded)
	•	Register/memory read

Efficient (multi-threaded, async, cancellable)
	•	DWARF/ELF/Mach-O parsing
	•	Symbol search (with indexing)
	•	Call graph generation
	•	Large binary support (2.5GB+ tested)
	•	Progress bars for any multi-second ops

Benchmarks (targeted)

Task	Target Time
Launch & attach (cold start)	< 150ms
Set breakpoint (known symbol)	< 10ms
Search 100k symbols	< 250ms
DWARF parse 2.5GB ELF	< 2s


⸻

🧠 Implementation Notes

Mach Kernel Integration
	•	Use mach_port_t to fetch threads, task state
	•	thread_get_state() for register dump (support for ARM_THREAD_STATE64)
	•	mach_vm_read / mach_vm_write for memory inspection
	•	ptrace(PT_ATTACH/TRACE_ME) to manage process control

ELF + DWARF Parsing
	•	DWARF: Parsed via gimli crate
	•	Mach-O parsing via object crate
	•	Index symbols with custom BTree-based radix trie

Thread Handling
	•	Dynamic thread list refresh
	•	Thread name lookup via pthread_getname_np
	•	Can freeze all threads except one

Breakpoints
	•	Software breakpoints (INT 3) via patching
	•	Stores original byte for restoration
	•	Can handle inline functions via DWARF mapping

⸻

⚠ Limitations

Limitation	Reason
macOS-only	Uses Mach kernel and ptrace APIs
ARM64-only	Apple M1/M2 register sets only supported
No GUI	TUI by choice. GUI support out-of-scope
No remote debugging	Designed for localhost use (but works over SSH)
Native code only	DWARF, not VM-level (no Python, JVM, etc)


⸻

🛠 Development Stack
	•	Language: Rust (nightly where needed)
	•	Build: Cargo
	•	Debugger Core: Custom engine
	•	TUI: tui-rs, crossterm, ratatui
	•	Parser Libraries: goblin, gimli, object, mach2
	•	Testing Targets: ClickHouse, Firefox, Chromium

⸻

🔮 Roadmap

v0.1 (Alpha)
	•	Load & attach
	•	Register/memory view
	•	Breakpoints
	•	Stepping
	•	TUI layout

v0.2
	•	Stack unwinding
	•	Source code mapping
	•	Async symbol loading
	•	Progress indicators
	•	Search index

v0.3+
	•	Inline function stepping
	•	DWARF call graph
	•	Thread pinning/debugging
	•	Visual memory inspector (hex + ASCII)
	•	Panic-safe runtime
	•	Variable inspection and expression evaluation

⸻

🧬 Philosophy

You shouldn't wait to debug your code.
You shouldn't fight your tools.
You shouldn't be forced to read Apple crash dumps to learn assembly.

Rustcat is the debugger Mac deserves. Clean. Deterministic. Free.
No more syscalls in the dark. Let's light this up.
