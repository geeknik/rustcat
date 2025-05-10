#!/bin/bash
# This script simulates the GitHub Actions workflow to ensure it works before pushing

set -e  # Exit on error

echo "🧪 Testing GitHub Actions workflow locally..."
echo ""

echo "Step 1: Building the project on current platform"
cargo build --verbose

echo ""
echo "Step 2: Running tests on current platform"
cargo test --verbose

echo ""
echo "Step 3: Checking for additional issues"
cargo check

echo ""

if [[ "$(uname)" == "Darwin" ]]; then
    echo "✅ Running on macOS - all tests should pass as expected"
else
    echo "⚠️  NOTE: Running on non-macOS platform. The code compiles thanks to our platform-specific scaffolding,"
    echo "    but full functionality is only available on macOS with Apple Silicon."
fi

echo ""
echo "👍 CI workflow simulation completed successfully!" 