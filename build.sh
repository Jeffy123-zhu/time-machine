#!/bin/bash
# build.sh
# Build script for eBPF Time Machine

set -e

echo "╔═══════════════════════════════════════════════════╗"
echo "║     Building eBPF Time Machine                   ║"
echo "╚═══════════════════════════════════════════════════╝"
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Check tools
check_tool() {
    if ! command -v $1 &> /dev/null; then
        echo -e "${RED}✗ $1 not found${NC}"
        echo "  Install: sudo apt install $2"
        exit 1
    fi
    echo -e "${GREEN}✓${NC} $1"
}

echo "Checking dependencies..."
check_tool clang clang
check_tool llvm-strip llvm
check_tool bpftool linux-tools-common
check_tool gcc gcc

echo -e "${GREEN}✓${NC} Kernel: $(uname -r)"

if [ ! -f "/sys/kernel/btf/vmlinux" ]; then
    echo -e "${YELLOW}⚠${NC} BTF not found (some features may not work)"
fi

echo ""
mkdir -p build

# Compile BPF
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "📦 Compiling eBPF programs..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

clang -g -O2 -target bpf \
    -D__TARGET_ARCH_x86_64 \
    -D__BPF_TRACING__ \
    -I/usr/include/bpf \
    -I./src/bpf \
    -c src/bpf/tracer.bpf.c \
    -o build/tracer.bpf.o

echo -e "${GREEN}✓${NC} BPF object: build/tracer.bpf.o"

llvm-strip -g build/tracer.bpf.o
echo -e "${GREEN}✓${NC} Stripped"

# Generate skeleton
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🦴 Generating skeleton..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

bpftool gen skeleton build/tracer.bpf.o > src/tracer.skel.h
echo -e "${GREEN}✓${NC} Skeleton: src/tracer.skel.h"

# Compile userspace
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🔧 Compiling userspace..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

gcc -g -Wall -Wextra \
    -I/usr/include/bpf \
    -I./src/bpf \
    -I./src \
    src/main.c \
    -o build/timemachine \
    -lbpf -lelf -lz

echo -e "${GREEN}✓${NC} Binary: build/timemachine"

# Compile demo
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🎬 Compiling demo..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if [ -f "examples/crash_demo.c" ]; then
    gcc -g -O0 examples/crash_demo.c -o build/crash_demo
    echo -e "${GREEN}✓${NC} Demo: build/crash_demo"
fi

# Capabilities
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🔐 Setting capabilities..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if [ "$EUID" -eq 0 ]; then
    setcap cap_sys_admin,cap_bpf,cap_perfmon,cap_dac_override=eip build/timemachine
    echo -e "${GREEN}✓${NC} Capabilities set"
else
    echo -e "${YELLOW}⚠${NC} Not root. Run to enable non-root:"
    echo "  sudo setcap cap_sys_admin,cap_bpf,cap_perfmon=eip build/timemachine"
fi

# Success
echo ""
echo "╔═══════════════════════════════════════════════════╗"
echo "║     ✅ Build Successful!                         ║"
echo "╚═══════════════════════════════════════════════════╝"
echo ""
echo "Quick start:"
echo ""
echo "  1. Run demo:"
echo "     ./build/crash_demo &"
echo ""
echo "  2. Start recording:"
echo "     sudo ./build/timemachine record \$(pgrep crash_demo)"
echo ""
echo "  3. Watch the crash get detected!"
echo ""
