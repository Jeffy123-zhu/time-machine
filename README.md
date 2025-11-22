# eBPF Time Machine

A debugging tool that uses eBPF to "time travel" through program crashes.

## What it does

When your program crashes, you usually only see the crash moment. Time Machine records everything that happened before, so you can "rewind" and see what led to the crash.

**Key features:**
- Records function calls, memory allocations, and system calls
- Automatically detects crashes (SIGSEGV, SIGABRT, etc.)
- Shows you what happened before the crash
- Helps find use-after-free bugs and memory leaks

## Why eBPF?

- **Low overhead**: Runs in kernel space, minimal performance impact
- **No code changes**: Attach to any running process
- **Safe**: Can't crash the kernel or target program

## Quick Start

### Requirements

- Linux kernel 5.8+ (with BTF support)
- clang, llvm, libbpf-dev, bpftool

On Ubuntu/Debian:
```bash
sudo apt install clang llvm libbpf-dev linux-tools-common linux-tools-generic
```

### Build

```bash
make
```

### Demo

The included demo program has a use-after-free bug that crashes on purpose.

**Terminal 1** - Run the buggy program:
```bash
./build/crash_demo &
```

**Terminal 2** - Start recording:
```bash
sudo ./build/timemachine record $(pgrep crash_demo)
```

When it crashes, you'll see:
```
===================================================
CRASH DETECTED!
===================================================
Timestamp: 1234567890123456
Signal: SIGSEGV (Segmentation fault)
PID: 12345

Use rewind to see what happened:
  ./timemachine rewind 1234567890123456
===================================================
```

**Rewind to see the bug:**
```bash
sudo ./build/timemachine rewind 1234567890123456
```

Output shows what happened before the crash:
```
Timestamp            PID      Type         Address            Details
────────────────────────────────────────────────────────────────────
    ...885000000     12345    ALLOC        0x7f1234567890     size=1024
    ...886000000     12345    FUNC_ENTRY   process_request    args=42
    ...887000000     12345    FREE         0x7f1234567890     (freed)
>>> ...890123456     12345    SIGNAL       sig=11 (SIGSEGV)   CRASH!
```

You can clearly see: memory was freed, then accessed → use-after-free bug!

## How it works

**eBPF programs** (in kernel space):
- `uprobe/uretprobe` - Track function calls
- `tracepoint` - Catch signals (crashes)
- Ring buffer - Send events to userspace

**Userspace program**:
- Collects events in a circular buffer
- Detects crashes automatically
- Lets you "rewind" to see what happened

**Event types tracked:**
- Function entry/exit
- Memory alloc/free
- System calls
- Signals (crashes)

## Project Structure

```
.
├── src/
│   ├── main.c              # Userspace collector
│   └── bpf/
│       ├── tracer.bpf.c    # eBPF programs
│       └── events.h        # Event definitions
├── examples/
│   └── crash_demo.c        # Demo with use-after-free bug
├── Makefile
└── README.md
```

## Limitations

- Only tracks one process at a time
- Limited event buffer (100k events)
- Requires root or CAP_BPF capability
- Linux 5.8+ only

## Future Ideas

- Web UI for visualization
- Multi-process tracking
- Network event tracking
- Integration with Cilium

## License

GPL-2.0 (required for eBPF programs)

---

Built for eBPF/Cilium Hackathon
