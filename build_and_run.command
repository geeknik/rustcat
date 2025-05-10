#!/bin/bash
cd "$(dirname "$0")"

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Build the project
echo -e "${GREEN}Building RUSTCAT...${NC}"
cargo build

# Check if build was successful
if [ $? -eq 0 ]; then
    echo -e "${GREEN}Build successful!${NC}"
    
    # Run the program if an argument was provided
    if [ "$1" != "" ]; then
        echo -e "${GREEN}Running RUSTCAT with target: $1${NC}"
        echo ""
        cargo run -- "$@"
    else
        echo -e "${GREEN}Run with a target program:${NC}"
        echo "./run.command /path/to/program"
    fi
else
    echo -e "${RED}Build failed!${NC}"
fi
