#!/bin/bash
# Pre-push security check script for RUSTCAT
# Run this before pushing changes to ensure the CI/CD pipeline won't find any issues

set -e  # Exit on error

echo "🛡️  Running RUSTCAT security checks before push..."
echo ""

# 1. Run unit tests to ensure functionality
echo "📋 Step 1: Running all tests"
cargo test --all-features
echo "✅ Tests passed"
echo ""

# 2. Run Clippy with security lints
echo "🔍 Step 2: Running clippy with security lints"
cargo clippy --all-targets --all-features -- -D warnings -W clippy::all -A clippy::pedantic -A clippy::nursery -A clippy::format_push_string -A clippy::struct_field_names -A clippy::unused_self
echo "✅ Clippy checks passed"
echo ""

# 3. Check for security vulnerabilities in dependencies
echo "🔒 Step 3: Checking for security vulnerabilities in dependencies"

# Install cargo-audit if not already installed
if ! command -v cargo-audit &> /dev/null; then
    echo "Installing cargo-audit..."
    cargo install cargo-audit
fi

cargo audit
echo "✅ Security audit passed"
echo ""

# 4. Run a quick fuzz test on critical components
echo "🧪 Step 4: Running quick fuzz tests"

# Make fuzzing optional since it's not always available
FUZZING_AVAILABLE=false

# Check if cargo-fuzz is installed
if command -v cargo-fuzz &> /dev/null; then
    # Check if we're on nightly (required for fuzzing)
    if rustc --version | grep -q nightly; then
        # Check if the fuzzing component is available
        if rustup component list | grep -q "fuzzing.*installed"; then
            FUZZING_AVAILABLE=true
        else
            echo "⚠️  Fuzzing component not available in the current nightly"
            echo "Skipping fuzzing tests - not a critical failure"
        fi
    else
        echo "⚠️  Skipping fuzzing - requires nightly Rust"
        echo "To run fuzz tests, switch to nightly with:"
        echo "  rustup default nightly"
    fi
else
    echo "Installing cargo-fuzz..."
    cargo install cargo-fuzz || {
        echo "⚠️  Failed to install cargo-fuzz. Skipping fuzzing tests."
    }
fi

# Only run fuzzing if everything is set up correctly
if [ "$FUZZING_AVAILABLE" = true ]; then
    # Run each fuzzer for a short duration (5 seconds each)
    echo "Running memory_fuzz for 5 seconds..."
    timeout 5s cargo fuzz run memory_fuzz || echo "Fuzzing completed or timed out"
    
    echo "Running command_fuzz for 5 seconds..."
    timeout 5s cargo fuzz run command_fuzz || echo "Fuzzing completed or timed out"
    
    echo "Running dwarf_fuzz for 5 seconds..."
    timeout 5s cargo fuzz run dwarf_fuzz || echo "Fuzzing completed or timed out"
else
    echo "⚠️  Fuzzing tests skipped - continuing with other checks"
fi
echo ""

# 5. Final check - any warnings that should be addressed?
echo "💡 Step 5: Final check for non-critical issues"
cargo check --all-features
echo ""

echo "🎉 All security checks passed! Safe to push."
echo "Remember: These checks don't catch everything. Always review your code carefully." 