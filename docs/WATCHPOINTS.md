# Watchpoints in RUSTCAT

Watchpoints are a powerful debugging feature in RUSTCAT that allow you to monitor memory accesses, helping you identify when and where specific memory locations are read from or written to. This is particularly useful for diagnosing:

- Memory corruption issues
- Unexpected variable modifications
- Race conditions
- Buffer overflows

## Watchpoint Types

RUSTCAT supports three types of watchpoints:

1. **Read Watchpoints**: Trigger when the specified memory is read from.
2. **Write Watchpoints**: Trigger when the specified memory is written to.
3. **Read/Write Watchpoints**: Trigger when the specified memory is either read from or written to.

## Hardware Implementation

On Apple Silicon (M1/M2) processors, RUSTCAT implements watchpoints using hardware debug registers:

- Up to 4 hardware watchpoints are supported simultaneously
- Watchpoint sizes can be 1, 2, 4, or 8 bytes
- No performance impact when watchpoints are active (unlike software watchpoints)

## Setting Watchpoints

### Command Line Interface

To set watchpoints, use the following commands in the RUSTCAT command input (press `:` to access):

```
watch <address>           # Set a read/write watchpoint
rwatch <address>          # Set a read watchpoint
wwatch <address>          # Set a write watchpoint
```

The address can be:

- A hexadecimal memory address (e.g., `0x1000`)
- A variable name (e.g., `counter`)
- An expression that evaluates to an address (e.g., `&counter`)

Examples:

```
watch 0x1000               # Watch 8 bytes at address 0x1000 for reads and writes
rwatch ptr                 # Watch the 'ptr' variable for reads
wwatch *ptr                # Watch the value pointed to by 'ptr' for writes
```

### UI Interaction

You can also set watchpoints through the memory view UI:

1. Navigate to the memory view (press `m`)
2. Locate the address you want to watch
3. Right-click on the address to open the context menu
4. Select "Set Watchpoint" and choose the type (Read/Write/Both)

## Removing Watchpoints

To remove watchpoints, use:

```
unwatch <id>              # Remove a watchpoint by ID (e.g., wp1)
unwatch <address>         # Remove a watchpoint at the specified address
```

To list all active watchpoints:

```
watchlist                  # Display all active watchpoints
```

## Visual Indication

In the memory view, addresses covered by watchpoints are highlighted:

- **Blue**: Read watchpoints
- **Red**: Write watchpoints
- **Magenta**: Read/Write watchpoints

This highlighting makes it easy to identify which memory areas are being monitored.

## Example: Using Watchpoints with watchpoint_demo.c

The `examples/watchpoint_demo.c` program demonstrates a simple use case for watchpoints.

1. Compile and run the demo:

   ```
   cd examples
   gcc -g watchpoint_demo.c -o watchpoint_demo
   cd ..
   cargo run -- ./examples/watchpoint_demo
   ```

2. Pause the program execution:
   - Press `g` to start execution
   - Press any key to pause when you see the counter incrementing

3. Set a watchpoint on the counter variable:
   - Press `:` to enter command mode
   - Type `memory <counter_address> 8` to view the memory (use the address printed by the program)
   - Type `watch <counter_address>` to set a read/write watchpoint

4. Resume execution:
   - Press `g` to continue
   - The program will stop automatically when the counter is read or written
   - You can see which instruction accessed the memory and how it was accessed

5. Observe the different watchpoint types:
   - Try setting read-only (`rwatch`) and write-only (`wwatch`) watchpoints
   - Notice how they trigger differently based on how the memory is accessed

## Implementation Details

RUSTCAT implements watchpoints using ARM64 debug registers on Apple Silicon:

- DBGWVR (Watchpoint Value Registers): Store the address to monitor
- DBGWCR (Watchpoint Control Registers): Configure the watchpoint behavior

The watchpoint configuration includes:

- Address to monitor
- Access type (read, write, or both)
- Size of the memory region (1, 2, 4, or 8 bytes)

When a watched memory location is accessed, the CPU triggers a debug exception, which RUSTCAT catches to pause execution and notify the user.

## Limitations

- Maximum of 4 hardware watchpoints can be active simultaneously
- Each watchpoint can monitor up to 8 bytes of contiguous memory
- If you need to monitor larger regions, you'll need multiple watchpoints
- Watchpoints only trigger for exact address matches, not for aliased memory

## Tips for Effective Use

- Use watchpoints sparingly to diagnose specific issues
- For large data structures, set watchpoints on specific fields that you suspect are being corrupted
- Combined with conditional breakpoints, watchpoints can help isolate complex issues
- The "Memory" view highlights watchpoints, making it easy to visualize monitored areas

## Troubleshooting

If watchpoints aren't behaving as expected:

1. Verify the exact address you're monitoring (use the `info` command on variables)
2. Check if you're using the right watchpoint type for your scenario
3. Remember that only 4 watchpoints can be active at once
4. Ensure the size of the watched region covers the entire variable
