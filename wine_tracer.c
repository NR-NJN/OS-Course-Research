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
    if (strstr(e->func_name, "_ret")) {
        printf("PID %d: %s returned %d\n", e->pid, e->func_name, e->ret_val);
    } else {
        printf("PID %d: %s called\n", e->pid, e->func_name);
    }
}

void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt) {
    printf("Lost %llu events on CPU #%d!\n", lost_cnt, cpu);
}

int main() {
    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
    struct bpf_object *obj;
    int map_fd;
    struct perf_buffer *pb = NULL;
    int err = 0;

    signal(SIGINT, sig_handler);

    setrlimit(RLIMIT_MEMLOCK, &r);

    obj = bpf_object__open_file("wine_tracer.bpf.o", NULL);
    if (!obj) {
        fprintf(stderr, "Failed to open BPF object\n");
        return 1;
    }
    if (bpf_object__load(obj)) {
        fprintf(stderr, "Failed to load BPF object\n");
        return 1;
    }

    map_fd = bpf_object__find_map_fd_by_name(obj, "events");
    if (map_fd < 0) {
        fprintf(stderr, "Failed to find map\n");
        return 1;
    }

    pb = perf_buffer__new(map_fd, 8, handle_event, handle_lost_events, NULL, NULL);
    if (!pb) {
        fprintf(stderr, "Failed to create perf buffer\n");
        return 1;
    }

    printf("Tracing Wine NtCreateKey... Press Ctrl+C to stop.\n");
    while (!exiting) {
        err = perf_buffer__poll(pb, 100);
        if (err < 0 && err != -EINTR) {
            printf("Error polling perf buffer: %d\n", err);
            break;
        }
    }

    perf_buffer__free(pb);
    bpf_object__close(obj);
    return 0;
}
