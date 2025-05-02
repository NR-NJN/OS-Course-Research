#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

struct event {
    int pid;
    int ret_val;
    char func_name[32];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __type(key, int);
    __type(value, int);
} events SEC(".maps");


SEC("uprobe//usr/lib/x86_64-linux-gnu/wine/x86_64-windows/ntdll.dll:NtCreateKey")
int trace_entry(struct pt_regs *ctx) {
    struct event e = {};
    e.pid = bpf_get_current_pid_tgid() >> 32;
    __builtin_memcpy(e.func_name, "NtCreateKey", 12);
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &e, sizeof(e));
    return 0;
}


SEC("uretprobe//usr/lib/x86_64-linux-gnu/wine/x86_64-windows/ntdll.dll:NtCreateKey")
int trace_exit(struct pt_regs *ctx) {
    struct event e = {};
    e.pid = bpf_get_current_pid_tgid() >> 32;
    e.ret_val = PT_REGS_RC(ctx);
    __builtin_memcpy(e.func_name, "NtCreateKey_ret", 15);
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &e, sizeof(e));
    return 0;
}

