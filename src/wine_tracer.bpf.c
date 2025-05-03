#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
 

char LICENSE[] SEC("license") = "GPL";

#define MAX_PATH_LEN 256

 
struct event {
    u32 pid;
    char comm[16];
    char oldpath[MAX_PATH_LEN];
    char newpath[MAX_PATH_LEN];
    int ret;
};

 
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __type(key, int);
    __type(value, int);
} events SEC(".maps");

 
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);            
    __type(key, u32);                  
    __type(value, struct event);      
} tmp_event_map SEC(".maps");

 
 


SEC("tp/syscalls/sys_enter_renameat2")
int handle_sys_enter_renameat2(struct trace_event_raw_sys_enter *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 map_key = 0;  
    struct event *e_ptr;  

     
    e_ptr = bpf_map_lookup_elem(&tmp_event_map, &map_key);
    if (!e_ptr) {
         
        return 0;
    }

     
     
     
     
    __builtin_memset(e_ptr, 0, sizeof(struct event));

     
    e_ptr->pid = pid_tgid >> 32;
    bpf_get_current_comm(&e_ptr->comm, sizeof(e_ptr->comm));

     
     
    char expected_comm[] = "wineserver";
    bool match = true;
    #pragma unroll  
    for (int i = 0; i < sizeof(expected_comm) - 1; ++i) {
        if (e_ptr->comm[i] != expected_comm[i]) {
            match = false;
            break;
        }
    }
    if (!match || e_ptr->comm[sizeof(expected_comm)-1] != 0) {
        return 0;  
    }
     

     
    const char *oldpath_ptr = (const char *)ctx->args[1];
    const char *newpath_ptr = (const char *)ctx->args[3];
    bpf_probe_read_user_str(&e_ptr->oldpath, sizeof(e_ptr->oldpath), oldpath_ptr);
    bpf_probe_read_user_str(&e_ptr->newpath, sizeof(e_ptr->newpath), newpath_ptr);

     
     
    e_ptr->newpath[MAX_PATH_LEN - 1] = '\0';  
    unsigned int newpath_len = 0;
     
    #pragma unroll
    for (int i = 0; i < MAX_PATH_LEN; i++) {
        if (e_ptr->newpath[i] == 0) {
            newpath_len = i;
            break;
        }
    }
    if (newpath_len == 0) return 0;  

     
    bool is_reg_file = false;
    if (newpath_len >= 4) {
        if (e_ptr->newpath[newpath_len - 4] == '.' &&
            e_ptr->newpath[newpath_len - 3] == 'r' &&
            e_ptr->newpath[newpath_len - 2] == 'e' &&
            e_ptr->newpath[newpath_len - 1] == 'g') {
            is_reg_file = true;
        }
    }
    if (!is_reg_file) {
        return 0;  
    }
     

     
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, e_ptr, sizeof(struct event));
    return 0;
}

SEC("tp/syscalls/sys_exit_renameat2")
int handle_sys_exit_renameat2(struct trace_event_raw_sys_exit *ctx) {
     
    return 0;
}

