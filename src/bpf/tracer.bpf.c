// tracer.bpf.c
// eBPF programs for Time Machine

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "events.h"

char LICENSE[] SEC("license") = "GPL";

// Function tracing
SEC("uprobe/func")
int trace_func_enter(struct pt_regs *ctx) {
    if (!should_trace())
        return 0;
    
    struct event_data *evt = get_event_buf();
    if (!evt)
        return 0;
    
    fill_common_fields(evt, EVENT_FUNC_ENTRY);
    
    evt->ip = PT_REGS_IP(ctx);
    evt->sp = PT_REGS_SP(ctx);
    evt->bp = PT_REGS_FP(ctx);
    
    evt->data.func.func_addr = evt->ip;
    evt->data.func.args[0] = PT_REGS_PARM1(ctx);
    evt->data.func.args[1] = PT_REGS_PARM2(ctx);
    evt->data.func.args[2] = PT_REGS_PARM3(ctx);
    evt->data.func.args[3] = PT_REGS_PARM4(ctx);
    evt->data.func.args[4] = PT_REGS_PARM5(ctx);
    evt->data.func.args[5] = PT_REGS_PARM6(ctx);
    
    evt->stack_id = bpf_get_stackid(ctx, &stack_traces, BPF_F_USER_STACK);
    
    submit_event(evt);
    return 0;
}

SEC("uretprobe/func")
int trace_func_exit(struct pt_regs *ctx) {
    if (!should_trace())
        return 0;
    
    struct event_data *evt = get_event_buf();
    if (!evt)
        return 0;
    
    fill_common_fields(evt, EVENT_FUNC_EXIT);
    
    evt->ip = PT_REGS_IP(ctx);
    evt->data.func.retval = PT_REGS_RC(ctx);
    evt->stack_id = bpf_get_stackid(ctx, &stack_traces, BPF_F_USER_STACK);
    
    submit_event(evt);
    return 0;
}
    fill_common_fields(evt, EVENT_FUNC_EXIT);
    evt->ip = PT_REGS_IP(ctx);
    evt->data.func.func_addr = evt->ip;
    evt->data.func.retval = PT_REGS_RC(ctx);
    
    submit_event(evt);
    return 0;
}

// Memory tracing
SEC("uprobe/malloc")
int trace_malloc_enter(struct pt_regs *ctx) {
    if (!should_trace())
        return 0;
    
    struct event_data *evt = get_event_buf();
    if (!evt)
        return 0;
    
    fill_common_fields(evt, EVENT_ALLOC);
    evt->ip = PT_REGS_IP(ctx);
    evt->data.mem.size = PT_REGS_PARM1(ctx);
    
    submit_event(evt);
    return 0;
}

SEC("uretprobe/malloc")
int trace_malloc_exit(struct pt_regs *ctx) {
    if (!should_trace())
        return 0;
    
    __u64 addr = PT_REGS_RC(ctx);
    if (addr == 0)
        return 0;
    
    struct event_data *evt = get_event_buf();
    if (!evt)
        return 0;
    
    fill_common_fields(evt, EVENT_ALLOC);
    evt->data.mem.addr = addr;
    evt->stack_id = bpf_get_stackid(ctx, &stack_traces, BPF_F_USER_STACK);
    
    struct alloc_info info = {
        .size = 0,
        .timestamp = evt->timestamp,
        .stack_id = evt->stack_id,
    };
    bpf_map_update_elem(&active_allocs, &addr, &info, BPF_ANY);
    
    submit_event(evt);
    return 0;
}

SEC("uprobe/calloc")
int trace_calloc_enter(struct pt_regs *ctx) {
    if (!should_trace())
        return 0;
    
    struct event_data *evt = get_event_buf();
    if (!evt)
        return 0;
    
    fill_common_fields(evt, EVENT_ALLOC);
    
    __u64 nmemb = PT_REGS_PARM1(ctx);
    __u64 size = PT_REGS_PARM2(ctx);
    evt->data.mem.size = nmemb * size;
    evt->data.mem.flags = 1;
    
    submit_event(evt);
    return 0;
}

SEC("uretprobe/calloc")
int trace_calloc_exit(struct pt_regs *ctx) {
    return trace_malloc_exit(ctx);
}

SEC("uprobe/free")
int trace_free(struct pt_regs *ctx) {
    if (!should_trace())
        return 0;
    
    __u64 addr = PT_REGS_PARM1(ctx);
    if (addr == 0)
        return 0;
    
    struct event_data *evt = get_event_buf();
    if (!evt)
        return 0;
    
    fill_common_fields(evt, EVENT_FREE);
    evt->data.mem.addr = addr;
    evt->ip = PT_REGS_IP(ctx);
    evt->stack_id = bpf_get_stackid(ctx, &stack_traces, BPF_F_USER_STACK);
    
    bpf_map_delete_elem(&active_allocs, &addr);
    
    submit_event(evt);
    return 0;
}

// Signal handling
SEC("tracepoint/signal/signal_deliver")
int trace_signal(void *ctx) {
    if (!should_trace())
        return 0;
    
    int sig;
    bpf_probe_read(&sig, sizeof(sig), ctx + 16);
    
    if (sig != 11 && sig != 6 && sig != 4 && sig != 8)
        return 0;
    
    struct event_data *evt = get_event_buf();
    if (!evt)
        return 0;
    
    fill_common_fields(evt, EVENT_SIGNAL);
    evt->data.sig.signal = sig;
    
    const char *sig_name = "CRASH";
    if (sig == 11) sig_name = "SIGSEGV";
    else if (sig == 6) sig_name = "SIGABRT";
    else if (sig == 4) sig_name = "SIGILL";
    else if (sig == 8) sig_name = "SIGFPE";
    
    __builtin_memcpy(evt->data.sig.info, sig_name, 
                     sizeof(evt->data.sig.info));
    
    submit_event(evt);
    return 0;
}

// System calls
SEC("tracepoint/raw_syscalls/sys_enter")
int trace_sys_enter(void *ctx) {
    if (!should_trace())
        return 0;
    
    struct event_data *evt = get_event_buf();
    if (!evt)
        return 0;
    
    fill_common_fields(evt, EVENT_SYSCALL);
    
    __u64 id;
    bpf_probe_read(&id, sizeof(id), ctx + 8);
    evt->data.syscall.nr = id;
    
    submit_event(evt);
    return 0;
}

// File operations
SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(void *ctx) {
    if (!should_trace())
        return 0;
    
    struct event_data *evt = get_event_buf();
    if (!evt)
        return 0;
    
    fill_common_fields(evt, EVENT_FILE_OP);
    
    const char *filename;
    bpf_probe_read(&filename, sizeof(filename), ctx + 24);
    bpf_probe_read_user_str(evt->data.file.path, 
                           sizeof(evt->data.file.path),
                           filename);
    
    submit_event(evt);
    return 0;
}


// Memory allocation tracking
SEC("uprobe/malloc")
int trace_malloc(struct pt_regs *ctx) {
    if (!should_trace())
        return 0;
    
    size_t size = (size_t)PT_REGS_PARM1(ctx);
    
    struct event_data *evt = get_event_buf();
    if (!evt)
        return 0;
    
    fill_common_fields(evt, EVENT_ALLOC);
    
    evt->data.mem.size = size;
    evt->data.mem.flags = 0;
    evt->stack_id = bpf_get_stackid(ctx, &stack_traces, BPF_F_USER_STACK);
    
    submit_event(evt);
    return 0;
}

SEC("uretprobe/malloc")
int trace_malloc_ret(struct pt_regs *ctx) {
    if (!should_trace())
        return 0;
    
    __u64 addr = PT_REGS_RC(ctx);
    if (!addr)
        return 0;
    
    // Store allocation info for later free tracking
    struct alloc_info info = {0};
    info.timestamp = bpf_ktime_get_ns();
    info.stack_id = bpf_get_stackid(ctx, &stack_traces, BPF_F_USER_STACK);
    
    bpf_map_update_elem(&active_allocs, &addr, &info, BPF_ANY);
    
    struct event_data *evt = get_event_buf();
    if (!evt)
        return 0;
    
    fill_common_fields(evt, EVENT_ALLOC);
    evt->data.mem.addr = addr;
    evt->stack_id = info.stack_id;
    
    submit_event(evt);
    return 0;
}

// Free tracking
SEC("uprobe/free")
int trace_free(struct pt_regs *ctx) {
    if (!should_trace())
        return 0;
    
    __u64 addr = ((__u64)PT_REGS_PARM1(ctx));
    if (!addr)
        return 0;
    
    struct event_data *evt = get_event_buf();
    if (!evt)
        return 0;
    
    fill_common_fields(evt, EVENT_FREE);
    evt->data.mem.addr = addr;
    
    // Check if this was a tracked allocation
    struct alloc_info *info = bpf_map_lookup_elem(&active_allocs, &addr);
    if (info) {
        evt->data.mem.size = info->size;
        evt->stack_id = bpf_get_stackid(ctx, &stack_traces, BPF_F_USER_STACK);
        bpf_map_delete_elem(&active_allocs, &addr);
    }
    
    submit_event(evt);
    return 0;
}

// Signal handling (crash detection)
SEC("tracepoint/signal/signal_deliver")
int trace_signal_deliver(struct trace_event_raw_signal_deliver *ctx) {
    if (!should_trace())
        return 0;
    
    int sig = ctx->sig;
    
    // Only track fatal signals
    if (sig != 11 && sig != 6 && sig != 4 && sig != 8)  // SIGSEGV, SIGABRT, SIGILL, SIGFPE
        return 0;
    
    struct event_data *evt = get_event_buf();
    if (!evt)
        return 0;
    
    fill_common_fields(evt, EVENT_SIGNAL);
    evt->data.sig.signal = sig;
    evt->data.sig.code = ctx->code;
    
    // Try to get some context
    const char *sig_names[] = {"", "", "", "", "SIGILL", "", "SIGABRT", "", "SIGFPE", "", "", "SIGSEGV"};
    if (sig < 12) {
        __builtin_memcpy(evt->data.sig.info, sig_names[sig], 16);
    }
    
    submit_event(evt);
    return 0;
}

// System call tracing (optional, for more context)
SEC("tracepoint/raw_syscalls/sys_enter")
int trace_sys_enter(struct trace_event_raw_sys_enter *ctx) {
    if (!should_trace())
        return 0;
    
    // Only trace interesting syscalls
    long id = ctx->id;
    if (id != 0 && id != 1 && id != 2 && id != 3)  // read, write, open, close
        return 0;
    
    struct event_data *evt = get_event_buf();
    if (!evt)
        return 0;
    
    fill_common_fields(evt, EVENT_SYSCALL);
    evt->data.syscall.nr = id;
    
    submit_event(evt);
    return 0;
}
