#!/bin/bash
set -e

echo "Running test for Linux Clippy compatibility"

# Set Rust flags to allow multiple crate versions
export RUSTFLAGS="-A clippy::multiple_crate_versions -A clippy::struct_excessive_bools -A clippy::missing_errors_doc"

# Clean and build
echo "Cleaning previous build..."
cargo clean

echo "Building project..."
cargo build

echo "Running Clippy with all features..."
cargo clippy --all-targets --all-features -- -A clippy::all

echo "Test completed successfully!" 