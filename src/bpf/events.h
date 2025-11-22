// events.h
// Event structure definitions for eBPF Time Machine

#ifndef __EVENTS_H
#define __EVENTS_H

#include <linux/types.h>

// Event type definitions
enum event_type {
    EVENT_FUNC_ENTRY = 1,
    EVENT_FUNC_EXIT = 2,
    EVENT_ALLOC = 3,
    EVENT_FREE = 4,
    EVENT_SYSCALL = 5,
    EVENT_NET_TX = 6,
    EVENT_NET_RX = 7,
    EVENT_FILE_OP = 8,
    EVENT_SIGNAL = 9,
    EVENT_THREAD = 10,
};

// Main event structure
struct event_data {
    // Header
    __u64 timestamp;
    __u32 pid;
    __u32 tid;
    __u16 type;
    __u16 cpu_id;
    __u32 flags;
    
    // Context info
    __u64 ip;
    __u64 sp;
    __u64 bp;
    __u64 return_addr;
    
    // Event-specific data
    union {
        struct {
            __u64 func_addr;
            __u64 args[6];
            __u64 retval;
        } func;
        
        struct {
            __u64 addr;
            __u64 size;
            __u64 old_addr;
            __u32 flags;
            __u32 callsite;
        } mem;
        
        struct {
            __u32 nr;
            __u32 pad;
            __u64 args[6];
            __s64 ret;
        } syscall;
        
        struct {
            __u32 saddr;
            __u32 daddr;
            __u16 sport;
            __u16 dport;
            __u32 len;
            __u16 proto;
            __u16 pad;
        } net;
        
        struct {
            __u32 fd;
            __u32 flags;
            __u64 offset;
            __u64 len;
            char path[40];
        } file;
        
        struct {
            __u32 signal;
            __u32 code;
            __u64 fault_addr;
            char info[48];
        } sig;
    } data;
    
    __s32 stack_id;
    __u32 _pad2;
};

// BPF maps
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024 * 1024);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u32);
    __type(value, __u8);
} tracked_pids SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(max_entries, 10000);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, 127 * sizeof(__u64));
} stack_traces SEC(".maps");

struct alloc_info {
    __u64 size;
    __u64 timestamp;
    __s32 stack_id;
    __u32 _pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 100000);
    __type(key, __u64);
    __type(value, struct alloc_info);
} active_allocs SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct event_data);
} scratch_event SEC(".maps");

// Helpers
static __always_inline int should_trace(void) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u8 *tracked = bpf_map_lookup_elem(&tracked_pids, &pid);
    return tracked && *tracked;
}

static __always_inline struct event_data* get_event_buf(void) {
    __u32 zero = 0;
    return bpf_map_lookup_elem(&scratch_event, &zero);
}

static __always_inline void submit_event(struct event_data *evt) {
    bpf_ringbuf_output(&events, evt, sizeof(*evt), 0);
}

static __always_inline void fill_common_fields(struct event_data *evt, __u16 type) {
    evt->timestamp = bpf_ktime_get_ns();
    evt->pid = bpf_get_current_pid_tgid() >> 32;
    evt->tid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    evt->type = type;
    evt->cpu_id = bpf_get_smp_processor_id();
}

#endif
