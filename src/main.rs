mod tui;
mod debugger;
mod platform;

use std::env;
use std::path::Path;
use std::process;

use anyhow::{anyhow, Result};
use log::{info, error, LevelFilter};

use debugger::core::Debugger;
use tui::app::App;

/// RUSTCAT - MacOS-only, Rust-based, fast-as-hell native debugger
fn main() -> Result<()> {
    // Initialize logging
    env_logger::Builder::new()
        .filter_level(LevelFilter::Info)
        .filter_module("rustcat", LevelFilter::Debug)
        .format_timestamp_secs()
        .init();
    
    info!("Starting RUSTCAT v0.1.0");
    
    // Parse command line arguments
    let args: Vec<String> = env::args().collect();
    
    // Check if we have at least one argument
    if args.len() < 2 {
        print_usage(&args[0]);
        process::exit(1);
    }
    
    // Process arguments
    let mut target_program = String::new();
    let mut program_args = Vec::new();
    let mut i = 1;
    
    while i < args.len() {
        match args[i].as_str() {
            // Version
            "-v" | "--version" => {
                println!("RUSTCAT v0.1.0");
                println!("A MacOS-Only, Rust-Based, Fast-as-Hell Native Debugger");
                println!("Built for macOS ARM64 (Apple Silicon)");
                process::exit(0);
            },
            // Help
            "-h" | "--help" => {
                print_usage(&args[0]);
                process::exit(0);
            },
            // Target program
            arg => {
                // Once we hit a non-flag argument, it's the target program
                // and the rest are arguments to the program
                target_program = arg.to_string();
                
                // Collect remaining arguments for the target program
                for j in (i + 1)..args.len() {
                    program_args.push(args[j].clone());
                }
                
                break;
            }
        }
        
        i += 1;
    }
    
    // Verify the target program exists
    if !Path::new(&target_program).exists() {
        error!("Target program not found: {}", target_program);
        process::exit(1);
    }
    
    // Initialize the debugger
    match init_debugger(&target_program, &program_args) {
        Ok(debugger) => {
            // Initialize the TUI app with the debugger
            info!("Initializing TUI");
            
            match App::new(debugger) {
                Ok(mut app) => {
                    // Run the app
                    if let Err(e) = app.run() {
                        error!("Error running application: {}", e);
                        process::exit(1);
                    }
                },
                Err(e) => {
                    error!("Error initializing application: {}", e);
                    process::exit(1);
                }
            }
        },
        Err(e) => {
            error!("Error initializing debugger: {}", e);
            process::exit(1);
        }
    }
    
    info!("RUSTCAT exiting");
    Ok(())
}

/// Initialize the debugger with the target program
fn init_debugger(target_program: &str, program_args: &[String]) -> Result<Debugger> {
    info!("Initializing debugger for {}", target_program);
    
    // Create a new debugger instance
    let mut debugger = Debugger::new(target_program)?;
    
    // Set program arguments (if any)
    if !program_args.is_empty() {
        debugger.set_args(program_args.to_vec());
    }
    
    // If the program doesn't contain a path separator, look for it in PATH
    if !target_program.contains('/') {
        if let Some(full_path) = find_in_path(target_program) {
            debugger.set_path(&full_path);
        }
    }
    
    // Load initial symbols (doesn't start the program yet)
    debugger.load_symbols()?;
    
    Ok(debugger)
}

/// Find a program in the PATH
fn find_in_path(program: &str) -> Option<String> {
    if let Ok(path) = env::var("PATH") {
        for dir in path.split(':') {
            let full_path = format!("{}/{}", dir, program);
            if Path::new(&full_path).exists() {
                return Some(full_path);
            }
        }
    }
    
    None
}

/// Print usage information
fn print_usage(program_name: &str) {
    println!("RUSTCAT - MacOS-only, Rust-based, fast-as-hell native debugger");
    println!("Usage: {} [options] program [args...]", program_name);
    println!();
    println!("Options:");
    println!("  -h, --help     Display this help message");
    println!("  -v, --version  Display version information");
    println!();
    println!("Keyboard Controls:");
    println!("  q              Quit");
    println!("  g              Run/continue program");
    println!("  b              Set breakpoint");
    println!("  s              Step instruction");
    println!("  c              Switch to code view");
    println!("  m              Switch to memory view");
    println!("  r              Switch to registers view");
    println!("  s              Switch to stack view");
    println!("  t              Switch to threads view");
    println!("  :              Switch to command mode");
}
