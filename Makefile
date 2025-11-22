# Makefile for eBPF Time Machine

CLANG ?= clang
LLC ?= llc
BPFTOOL ?= bpftool
CC ?= gcc

ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')
INCLUDES := -I/usr/include/bpf -I./src/bpf -I./src
CFLAGS := -g -Wall -Wextra $(INCLUDES)
LDFLAGS := -lbpf -lelf -lz

BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) -D__BPF_TRACING__

BUILD_DIR := build
SRC_DIR := src
BPF_DIR := $(SRC_DIR)/bpf
EXAMPLES_DIR := examples

BPF_OBJ := $(BUILD_DIR)/tracer.bpf.o
SKEL := $(SRC_DIR)/tracer.skel.h
TARGET := $(BUILD_DIR)/timemachine
DEMO := $(BUILD_DIR)/crash_demo

.PHONY: all clean demo install

all: $(TARGET) $(DEMO)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

# Compile eBPF program
$(BPF_OBJ): $(BPF_DIR)/tracer.bpf.c $(BPF_DIR)/events.h | $(BUILD_DIR)
	$(CLANG) $(BPF_CFLAGS) $(INCLUDES) -c $< -o $@
	llvm-strip -g $@

# Generate skeleton
$(SKEL): $(BPF_OBJ)
	$(BPFTOOL) gen skeleton $< > $@

# Compile userspace program
$(TARGET): $(SRC_DIR)/main.c $(SKEL) $(BPF_DIR)/events.h
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

# Compile demo program
$(DEMO): $(EXAMPLES_DIR)/crash_demo.c | $(BUILD_DIR)
	$(CC) -g -O0 $< -o $@

# Set capabilities (requires root)
install: $(TARGET)
	@echo "Setting capabilities..."
	sudo setcap cap_sys_admin,cap_bpf,cap_perfmon,cap_dac_override=eip $(TARGET)
	@echo "Done! You can now run without sudo."

demo: $(TARGET) $(DEMO)
	@echo ""
	@echo "╔═══════════════════════════════════════════════════╗"
	@echo "║     eBPF Time Machine - Demo Ready               ║"
	@echo "╚═══════════════════════════════════════════════════╝"
	@echo ""
	@echo "1. Run demo:     ./$(DEMO) &"
	@echo "2. Start tracer: sudo ./$(TARGET) record \$$(pgrep crash_demo)"
	@echo ""

clean:
	rm -rf $(BUILD_DIR)
	rm -f $(SKEL)

help:
	@echo "eBPF Time Machine - Build System"
	@echo ""
	@echo "Targets:"
	@echo "  all      - Build everything (default)"
	@echo "  demo     - Build and show demo instructions"
	@echo "  install  - Set capabilities for non-root usage"
	@echo "  clean    - Remove build artifacts"
	@echo "  help     - Show this help"
	@echo ""
	@echo "Usage:"
	@echo "  make"
	@echo "  make demo"
	@echo "  sudo make install"
