// SPDX-License-Identifier: GPL-3.0-or-later
#define main original_proc_main
#include "proc.c"
#undef main
#include <sched.h>

static void* retained_files(void* context) {
    CHECK(syscall(SYS_unshare, CLONE_FILES) == 0);
    for (unsigned at = 0; at < 4096; at++)
        CHECK(open("/dev/null", O_RDONLY | O_CLOEXEC) >= 0);
    return member(context);
}

int main(int argc, char** argv) {
    CHECK(argc == 1 || (argc == 2 && !strcmp(argv[1], "--held")));
    unsigned waited = 0, polls = 0;
    for (unsigned cycle = 0; cycle < 64; cycle++) {
        int ready[2], finish[2];
        CHECK(pipe(ready) == 0 && pipe(finish) == 0);
        struct member context = {ready[1], finish[0]};
        pthread_t thread;
        CHECK(pthread_create(&thread, NULL, retained_files, &context) == 0);
        pid_t tid;
        CHECK(read(ready[0], &tid, sizeof(tid)) == sizeof(tid));
        CHECK(account_process_busy(1010, (gid_t)-1) == 1);
        if (argc == 2) {
            // The original helper must reject a still-running kernel task.
            wait_thread_retired(tid);
            CHECK(0);
        }
        byte(finish[1], 1);
        CHECK(pthread_join(thread, NULL) == 0);
        unsigned current = wait_thread_retired(tid);
        waited += current != 0;
        polls += current;
        CHECK(account_process_busy(1010, (gid_t)-1) == 0);
        CHECK(status_file(tid, 0) == -1 && errno == ENOENT);
        for (unsigned side = 0; side < 2; side++)
            CHECK(close(ready[side]) == 0 && close(finish[side]) == 0);
    }
    CHECK(waited > 0);
    printf("PROC_RETIREMENT_PASS cycles=64 waited=%u polls=%u\n", waited, polls);
    return 0;
}
