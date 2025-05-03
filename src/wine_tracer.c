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
#include <stdint.h>
#include <inttypes.h>

static volatile sig_atomic_t exiting = 0;

 
#define MAX_PATH_LEN 256
struct event {
    uint32_t pid;
    char comm[16];
    char oldpath[MAX_PATH_LEN];
    char newpath[MAX_PATH_LEN];
    int ret;  
};

void sig_handler(int sig) { exiting = 1; }

void handle_event(void *ctx, int cpu, void *data, unsigned int data_sz) {
    struct event *e = data;

    if (data_sz < sizeof(*e)) {
        printf("Error: Malformed event data (size %u < %zu)\n", data_sz, sizeof(*e));
        return;
    }

     
    e->oldpath[MAX_PATH_LEN - 1] = '\0';
    e->newpath[MAX_PATH_LEN - 1] = '\0';
    e->comm[15] = '\0';

    printf("REG UPDATE DETECTED: PID %" PRIu32 " (%s) renamed '%s' -> '%s'\n",
           e->pid, e->comm, e->oldpath, e->newpath);
}

void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt) {
    fprintf(stderr, "Warning: Lost %llu events on CPU #%d!\n", lost_cnt, cpu);
}

 
 
int main() {
    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
    struct bpf_object *obj = NULL;
    struct perf_buffer *pb = NULL;
    int map_fd = -1, err = 0;

    signal(SIGINT, sig_handler); signal(SIGTERM, sig_handler);
    if (setrlimit(RLIMIT_MEMLOCK, &r)) { /* error handling */ return 1; }

     

    obj = bpf_object__open_file("wine_tracer.bpf.o", NULL);
    if (!obj) { err = -errno; /* error handling */ return 1; }
    if (bpf_object__load(obj)) { err = -errno; /* error handling */ bpf_object__close(obj); return 1; }
    printf("BPF object loaded successfully (tracepoints should be attached).\n");

    map_fd = bpf_object__find_map_fd_by_name(obj, "events");
    if (map_fd < 0) { err = map_fd; /* error handling */ goto cleanup; }

    pb = perf_buffer__new(map_fd, 8, handle_event, handle_lost_events, NULL, NULL);
    if (!pb) { err = -errno; /* error handling */ goto cleanup; }

     
    printf("Tracing 'renameat2' syscalls for registry updates... Press Ctrl+C to stop.\n");
    while (!exiting) {
        err = perf_buffer__poll(pb, 100);
        if (err < 0 && err != -EINTR) { err = -errno; break; }
        err = 0;
    }

cleanup:
    printf("\nExiting...\n");
    perf_buffer__free(pb);
    bpf_object__close(obj);
    return err;
}

