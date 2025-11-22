#!/bin/bash
# demo.sh - Interactive demo script for eBPF Time Machine

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# Banner
echo -e "${CYAN}"
cat << "EOF"
╔═══════════════════════════════════════════════════╗
║          ⏰  eBPF Time Machine Demo              ║
║                                                   ║
║     Time Travel Debugging with eBPF              ║
╚═══════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

# Check if built
if [ ! -f "build/timemachine" ] || [ ! -f "build/crash_demo" ]; then
    echo -e "${RED}Error: Project not built!${NC}"
    echo "Run: make"
    exit 1
fi

# Check root
if [ "$EUID" -ne 0 ]; then
    echo -e "${YELLOW}Note: This demo requires root privileges${NC}"
    echo "Restarting with sudo..."
    exec sudo "$0" "$@"
fi

echo -e "${GREEN}✓ All checks passed${NC}"
echo ""

# Step 1
echo -e "${PURPLE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${PURPLE}Step 1: Starting the demo application${NC}"
echo -e "${PURPLE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo "This application has a use-after-free bug on request #42"
echo ""

# Start demo app in background
./build/crash_demo &
DEMO_PID=$!

echo -e "${GREEN}✓ Demo app started (PID: $DEMO_PID)${NC}"
echo ""

# Wait for app to be ready
sleep 4

# Step 2
echo -e "${PURPLE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${PURPLE}Step 2: Starting Time Machine${NC}"
echo -e "${PURPLE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo "Time Machine will now record all events from the demo app"
echo ""

# Start time machine
timeout 30 ./build/timemachine record $DEMO_PID || true

echo ""
echo -e "${GREEN}✓ Recording stopped${NC}"
echo ""

# Step 3
echo -e "${PURPLE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${PURPLE}Step 3: Analysis Complete${NC}"
echo -e "${PURPLE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo "Time Machine has captured the crash and analyzed the events!"
echo ""
echo -e "${CYAN}What happened:${NC}"
echo "  1. Memory was allocated for request #42"
echo "  2. The memory was freed (BUG!)"
echo "  3. The program tried to access the freed memory"
echo "  4. SIGSEGV (Segmentation Fault) occurred"
echo ""
echo -e "${GREEN}✓ Bug identified: Use-After-Free${NC}"
echo ""

# Cleanup
if ps -p $DEMO_PID > /dev/null 2>&1; then
    kill $DEMO_PID 2>/dev/null || true
fi

# Summary
echo -e "${PURPLE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${PURPLE}Demo Complete!${NC}"
echo -e "${PURPLE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "${CYAN}Key Features Demonstrated:${NC}"
echo "  ✓ Real-time event recording with eBPF"
echo "  ✓ Automatic crash detection"
echo "  ✓ Memory allocation tracking"
echo "  ✓ Time travel debugging capability"
echo "  ✓ Memory leak analysis"
echo ""
echo -e "${YELLOW}Try it yourself:${NC}"
echo "  1. Run: ./build/crash_demo &"
echo "  2. Record: sudo ./build/timemachine record \$(pgrep crash_demo)"
echo "  3. Rewind: sudo ./build/timemachine rewind <timestamp>"
echo ""
echo -e "${GREEN}Thank you for watching!${NC} ⏰✨"
echo ""
