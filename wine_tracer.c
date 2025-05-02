#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <sys/resource.h>
#include <linux/perf_event.h>
#include <errno.h>
#include <string.h>

static volatile sig_atomic_t exiting = 0;

 
struct event {
    int pid;
    int ret_val;
    char func_name[32];  
};

void sig_handler(int sig) {
    exiting = 1;
}

void handle_event(void *ctx, int cpu, void *data, unsigned int data_sz) {
    struct event *e = data;
    if (data_sz >= sizeof(struct event) && strstr(e->func_name, "_ret")) {
        printf("PID %d: %s returned %d\n", e->pid, e->func_name, e->ret_val);
    } else if (data_sz >= sizeof(struct event)) {
        printf("PID %d: %s called\n", e->pid, e->func_name);
    } else {
        printf("Received malformed event data (size %u)\n", data_sz);
    }
}

void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt) {
    printf("Lost %llu events on CPU #%d!\n", lost_cnt, cpu);
}

int main() {
    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
    struct bpf_object *obj = NULL;
    struct perf_buffer *pb = NULL;
    struct bpf_program *prog_entry = NULL, *prog_exit = NULL;
    struct bpf_link *link_entry = NULL, *link_exit = NULL; 
    int map_fd = -1;
    int err = 0;


    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    if (setrlimit(RLIMIT_MEMLOCK, &r)) {
        fprintf(stderr, "Failed to set RLIMIT_MEMLOCK: %s\n", strerror(errno));
        return 1;
    }

     
    obj = bpf_object__open_file("wine_tracer.bpf.o", NULL);
    if (!obj) {
        fprintf(stderr, "Failed to open BPF object: %s\n", strerror(errno));
        return 1;
    }
    if (bpf_object__load(obj)) {
        fprintf(stderr, "Failed to load BPF object: %s\n", strerror(errno));
        bpf_object__close(obj);
        return 1;
    }

     
    map_fd = bpf_object__find_map_fd_by_name(obj, "events");
    if (map_fd < 0) {
        fprintf(stderr, "Failed to find map 'events': %s\n", strerror(errno));
        err = -1; goto cleanup;
    }

    pb = perf_buffer__new(map_fd, 8, handle_event, handle_lost_events, NULL, NULL);
    if (!pb) {
        err = -errno;  
        fprintf(stderr, "Failed to create perf buffer: %s\n", strerror(-err));
        goto cleanup;
    }

     
     
    const char *entry_prog_title = "uprobe//usr/lib/x86_64-linux-gnu/wine/x86_64-windows/ntdll.dll:NtCreateKey";
    const char *exit_prog_title = "uretprobe//usr/lib/x86_64-linux-gnu/wine/x86_64-windows/ntdll.dll:NtCreateKey";
    const char *binary_path = "/usr/lib/x86_64-linux-gnu/wine/x86_64-windows/ntdll.dll";  

    prog_entry = bpf_object__find_program_by_title(obj, entry_prog_title);
    if (!prog_entry) {
        fprintf(stderr, "Failed to find BPF program '%s'\n", entry_prog_title);
        err = -ENOENT; goto cleanup;
    }

    prog_exit = bpf_object__find_program_by_title(obj, exit_prog_title);
    if (!prog_exit) {
        fprintf(stderr, "Failed to find BPF program '%s'\n", exit_prog_title);
        err = -ENOENT; goto cleanup;
    }

     
     
    link_entry = bpf_program__attach_uprobe(prog_entry, false, -1, binary_path, 0);
    if (!link_entry) {
        err = -errno;  
        fprintf(stderr, "Failed to attach entry uprobe to %s: %s\n", binary_path, strerror(-err));
        goto cleanup;
    }
    printf("Attached entry probe successfully.\n");

     
    link_exit = bpf_program__attach_uprobe(prog_exit, true, -1, binary_path, 0);
    if (!link_exit) {
        err = -errno;  
        fprintf(stderr, "Failed to attach exit uretprobe to %s: %s\n", binary_path, strerror(-err));
        goto cleanup;
    }
    printf("Attached exit probe successfully.\n");

     
    printf("Tracing Wine NtCreateKey... Press Ctrl+C to stop.\n");
    while (!exiting) {
        err = perf_buffer__poll(pb, 100);  
        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "Error polling perf buffer: %s\n", strerror(-err));
            break;  
        }
         
        err = 0;
    }

cleanup:
    printf("Exiting...\n");
     
    if (link_entry) bpf_link__destroy(link_entry);
    if (link_exit) bpf_link__destroy(link_exit);
    perf_buffer__free(pb);  
    bpf_object__close(obj);  
    return -err;  
}

