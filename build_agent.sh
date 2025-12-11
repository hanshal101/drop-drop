#!/bin/bash
set -e

echo "Building Drop-Drop Agent..."

# Ensure we're in the correct directory
cd "$(dirname "$0")/agent"

# Install Go dependencies
go mod tidy

# Build the agent for the current platform
mkdir -p ../bin
go build -o ../bin/agent .

echo "Agent built successfully at ./bin/agent"
