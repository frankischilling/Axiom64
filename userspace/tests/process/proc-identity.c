// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define CHECK(expression)                                                                          \
    do {                                                                                           \
        if (!(expression)) {                                                                       \
            fprintf(stderr, "PROC_IDENTITY_FAIL line=%d errno=%d expression=%s\n", __LINE__,       \
                    errno, #expression);                                                           \
            exit(1);                                                                               \
        }                                                                                          \
    } while (0)

struct identity {
    pid_t pid;
    char state;
    unsigned long long start;
    long long parent, group, session, threads;
};

static unsigned observations;
static const char* executable;
static char boot[38];
static volatile sig_atomic_t expired;

static void unready_deadline(int signal) {
    expired = signal;
}

static void observed(const char* name) {
    printf("PROC_IDENTITY_OBSERVATION %s\n", name);
    fflush(stdout);
    observations++;
}

static void read_all(int fd, char* text, size_t capacity, size_t chunk) {
    size_t used = 0;
    for (;;) {
        CHECK(used + chunk <= capacity);
        ssize_t count = read(fd, text + used, chunk);
        CHECK(count >= 0);
        if (!count)
            break;
        used += (size_t)count;
    }
    text[used] = 0;
}

static int stat_file(pid_t group, pid_t member) {
    char path[96];
    CHECK(snprintf(path, sizeof(path), member ? "/proc/%d/task/%d/stat" : "/proc/%d/stat", group,
                   member) < (int)sizeof(path));
    return open(path, O_RDONLY | O_CLOEXEC);
}

static struct identity parse(const char* text) {
    struct identity result = {0};
    char* after = NULL;
    long id = strtol(text, &after, 10);
    CHECK(id > 0 && id <= 0x7fffffff && after && after[0] == ' ' && after[1] == '(');
    const char* close = strrchr(text, ')');
    CHECK(close && close[1] == ' ' && strchr("RSDZTtIX", close[2]) && close[3] == ' ');
    result.pid = (pid_t)id;
    result.state = close[2];
    const char* cursor = close + 4;
    for (unsigned field = 4; field <= 52; field++) {
        errno = 0;
        unsigned long long value = strtoull(cursor, &after, 10);
        CHECK(!errno && after != cursor &&
              (after[0] == ' ' || (field == 52 && after[0] == '\n' && !after[1])));
        if (field == 4)
            result.parent = value;
        else if (field == 5)
            result.group = value;
        else if (field == 6)
            result.session = value;
        else if (field == 20)
            result.threads = value;
        else if (field == 22) {
            CHECK(*cursor != '-');
            result.start = value;
        }
        cursor = after + 1;
    }
    return result;
}

static struct identity identity(pid_t group, pid_t member) {
    int fd = stat_file(group, member);
    CHECK(fd >= 0);
    char text[2048];
    read_all(fd, text, sizeof(text), 17);
    CHECK(close(fd) == 0);
    return parse(text);
}

static void boot_read(const char* path, char output[38]) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    CHECK(fd >= 0);
    struct stat value;
    CHECK(fstat(fd, &value) == 0 && S_ISREG(value.st_mode) && !value.st_uid && !value.st_gid &&
          (value.st_mode & 07777) == 0444 && value.st_nlink == 1);
    read_all(fd, output, 38, 1);
    CHECK(strlen(output) == 37 && output[36] == '\n' && output[14] == '4' &&
          strchr("89ab", output[19]));
    for (size_t i = 0; i < 36; i++)
        CHECK(i == 8 || i == 13 || i == 18 || i == 23
                  ? output[i] == '-'
                  : strchr("0123456789abcdef", output[i]) != NULL);
    CHECK(lseek(fd, 0, SEEK_SET) == 0);
    char again[38];
    read_all(fd, again, sizeof(again), 1);
    CHECK(!strcmp(output, again) && close(fd) == 0);
}

static unsigned long long now_ticks(void) {
    struct timespec value;
    CHECK(clock_gettime(CLOCK_BOOTTIME, &value) == 0 && value.tv_sec >= 0 && value.tv_nsec >= 0);
    long rate = sysconf(_SC_CLK_TCK);
    CHECK(rate == 100);
    return (unsigned long long)value.tv_sec * 100 + (unsigned long long)value.tv_nsec / 10000000;
}

static void byte(int fd, int writing) {
    char value = 'x';
    CHECK((writing ? write(fd, &value, 1) : read(fd, &value, 1)) == 1 && value == 'x');
}

static void reap(pid_t pid) {
    int status;
    CHECK(waitpid(pid, &status, 0) == pid && WIFEXITED(status) && !WEXITSTATUS(status));
}

static void pause_tick(void) {
    struct timespec interval = {0, 30000000};
    while (nanosleep(&interval, &interval) < 0)
        CHECK(errno == EINTR);
}

static void retired_thread(pid_t tid) {
    struct timespec started, now;
    CHECK(clock_gettime(CLOCK_MONOTONIC, &started) == 0);
    for (;;) {
        int fd = stat_file(getpid(), tid);
        if (fd < 0) {
            CHECK(errno == ENOENT);
            return;
        }
        CHECK(close(fd) == 0 && clock_gettime(CLOCK_MONOTONIC, &now) == 0);
        CHECK((now.tv_sec - started.tv_sec) * 1000000000LL + now.tv_nsec - started.tv_nsec <
              2000000000LL);
        struct timespec interval = {0, 1000000};
        while (nanosleep(&interval, &interval) < 0)
            CHECK(errno == EINTR);
    }
}

struct thread_context {
    int ready, finish;
};

static void* thread_member(void* opaque) {
    struct thread_context* context = opaque;
    pid_t tid = (pid_t)syscall(SYS_gettid);
    CHECK(write(context->ready, &tid, sizeof(tid)) == sizeof(tid));
    byte(context->finish, 0);
    return NULL;
}

static void replace(int receipt) {
    struct identity before = identity(getpid(), 0);
    char pid[24], start[24], descriptor[24];
    snprintf(pid, sizeof(pid), "%d", before.pid);
    snprintf(start, sizeof(start), "%llu", before.start);
    snprintf(descriptor, sizeof(descriptor), "%d", receipt);
    execl(executable, executable, "--after-exec", pid, start, descriptor, boot, (char*)NULL);
    CHECK(0);
}

static void* thread_exec(void* opaque) {
    replace(*(int*)opaque);
    return NULL;
}

static void exec_control(int member) {
    int receipt[2];
    CHECK(pipe(receipt) == 0);
    pid_t child = fork();
    CHECK(child >= 0);
    if (!child) {
        close(receipt[0]);
        if (member) {
            pause_tick();
            pthread_t thread;
            CHECK(pthread_create(&thread, NULL, thread_exec, &receipt[1]) == 0);
            for (;;)
                pause();
        }
        replace(receipt[1]);
    }
    close(receipt[1]);
    struct identity after;
    CHECK(read(receipt[0], &after, sizeof(after)) == sizeof(after) && after.pid == child);
    reap(child);
    CHECK(close(receipt[0]) == 0);
}

int main(int argc, char** argv) {
    executable = argv[0];
    if (argc == 2 && !strcmp(argv[1], "--unready")) {
        int fd = open("/proc/sys/kernel/random/boot_id", O_RDONLY | O_CLOEXEC);
        CHECK(fd >= 0);
        char value[2] = {'x', 'y'};
        struct iovec vectors[] = {{value, 1}, {value + 1, 1}};
        CHECK(pread(fd, value, 1, 0) == -1 && errno == EAGAIN && value[0] == 'x');
        int flags = fcntl(fd, F_GETFL);
        CHECK(flags >= 0 && fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0);
        CHECK(read(fd, value, 1) == -1 && errno == EAGAIN && value[0] == 'x');
        CHECK(readv(fd, vectors, 2) == -1 && errno == EAGAIN && value[0] == 'x' && value[1] == 'y');
        CHECK(fcntl(fd, F_SETFL, flags) == 0);
        struct sigaction action = {.sa_handler = unready_deadline};
        CHECK(sigemptyset(&action.sa_mask) == 0 && sigaction(SIGALRM, &action, NULL) == 0);
        // Bound a stalled syscall so the regular-file error regression fails
        // directly. This alarm does not change the entropy readiness policy.
        alarm(2);
        CHECK(read(fd, value, 1) == -1 && errno == EAGAIN && value[0] == 'x' && !expired);
        CHECK(lseek(fd, 0, SEEK_SET) == 0);
        CHECK(read(fd, value, 1) == -1 && errno == EAGAIN && value[0] == 'x' && !expired);
        CHECK(readv(fd, vectors, 2) == -1 && errno == EAGAIN && value[0] == 'x' &&
              value[1] == 'y' && !expired);
        alarm(0);
        CHECK(close(fd) == 0);
        observed("uninitialized_boot_id_fails_eagain_without_output");
        puts("PROC_IDENTITY_PASS observations=1 unready=1");
        return 0;
    }
    boot_read("/proc/sys/kernel/random/boot_id", boot);
    if (argc == 6 && !strcmp(argv[1], "--after-exec")) {
        struct identity after = identity(getpid(), 0);
        CHECK(after.pid == (pid_t)strtol(argv[2], NULL, 10) &&
              after.start == strtoull(argv[3], NULL, 10) && !strcmp(boot, argv[5]));
        int receipt = (int)strtol(argv[4], NULL, 10);
        CHECK(write(receipt, &after, sizeof(after)) == sizeof(after));
        return 0;
    }
    CHECK(argc == 1);
    printf("PROC_IDENTITY_BOOT %s", boot);
    char repeat[38];
    boot_read("/proc/sys/kernel/random/boot_id", repeat);
    CHECK(!strcmp(boot, repeat));
    char mountpoint[] = "/tmp/axiom-proc-identity-XXXXXX";
    CHECK(mkdtemp(mountpoint));
    CHECK(mount("proc", mountpoint, "proc", 0, NULL) == 0);
    char mounted[128];
    snprintf(mounted, sizeof(mounted), "%s/sys/kernel/random/boot_id", mountpoint);
    boot_read(mounted, repeat);
    CHECK(!strcmp(boot, repeat) && umount(mountpoint) == 0 && rmdir(mountpoint) == 0);
    int writable = open("/proc/sys/kernel/random/boot_id", O_WRONLY);
    if (writable >= 0) {
        CHECK(write(writable, "x", 1) == -1 && close(writable) == 0);
    }
    observed("boot_uuid_v4_partial_reads_rewind_and_multiple_mounts_are_stable");

    struct identity self = identity(getpid(), 0), leader = identity(getpid(), getpid());
    CHECK(self.pid == getpid() && self.parent == getppid() && self.group == getpgrp() &&
          self.session == getsid(0) && self.threads == 1 && self.start <= now_ticks());
    CHECK(leader.pid == self.pid && leader.start == self.start);
    int fd = open("/proc/self/stat", O_RDONLY | O_CLOEXEC);
    CHECK(fd >= 0);
    char text[2048];
    read_all(fd, text, sizeof(text), 1);
    CHECK(parse(text).start == self.start && close(fd) == 0);
    pause_tick();
    CHECK(identity(getpid(), 0).start == self.start);
    observed("self_pid_and_leader_stat_have_actual_clock_ticks_and_fixed_52_fields");

    int ready[2], finish[2];
    CHECK(pipe(ready) == 0 && pipe(finish) == 0);
    unsigned long long before = now_ticks();
    pid_t child = fork();
    CHECK(child >= 0);
    if (!child) {
        close(ready[0]);
        close(finish[1]);
        byte(ready[1], 1);
        byte(finish[0], 0);
        _exit(0);
    }
    close(ready[1]);
    close(finish[0]);
    byte(ready[0], 0);
    struct identity born = identity(child, 0);
    CHECK(born.pid == child && born.parent == getpid() && born.start >= before &&
          born.start <= now_ticks() && born.start > self.start);
    int buffered = stat_file(child, 0), unread = stat_file(child, 0);
    CHECK(buffered >= 0 && unread >= 0 && read(buffered, text, 1) == 1);
    byte(finish[1], 1);
    siginfo_t information;
    CHECK(waitid(P_PID, (id_t)child, &information, WEXITED | WNOWAIT) == 0 &&
          information.si_pid == child);
    CHECK(identity(child, 0).state == 'Z' && identity(child, 0).start == born.start);
    reap(child);
    read_all(buffered, text + 1, sizeof(text) - 1, 13);
    CHECK(parse(text).start == born.start);
    CHECK(read(unread, text, sizeof(text)) == -1 && errno == ESRCH);
    CHECK(lseek(buffered, 0, SEEK_SET) == 0 && read(buffered, text, 1) == -1 && errno == ESRCH);
    CHECK(stat_file(child, 0) == -1 && errno == ENOENT);
    close(buffered);
    close(unread);
    close(ready[0]);
    close(finish[1]);
    observed("fork_zombie_buffered_stat_and_reaped_fresh_or_rewound_reads");

    CHECK(pipe(ready) == 0 && pipe(finish) == 0);
    struct thread_context context = {ready[1], finish[0]};
    pthread_t thread;
    pause_tick();
    CHECK(pthread_create(&thread, NULL, thread_member, &context) == 0);
    pid_t tid;
    CHECK(read(ready[0], &tid, sizeof(tid)) == sizeof(tid) && tid != getpid());
    struct identity member = identity(getpid(), tid), direct = identity(tid, 0);
    CHECK(member.pid == tid && member.start > self.start && member.start <= now_ticks() &&
          member.threads == 2 && direct.pid == tid && direct.start == member.start);
    CHECK(identity(getpid(), 0).start == self.start);
    buffered = stat_file(getpid(), tid);
    unread = stat_file(getpid(), tid);
    CHECK(buffered >= 0 && unread >= 0 && read(buffered, text, 1) == 1);
    byte(finish[1], 1);
    CHECK(pthread_join(thread, NULL) == 0);
    // Linux may wake the joiner before detaching the exiting task from procfs.
    // Wait for kernel retirement before asserting fresh/rewound reads fail.
    retired_thread(tid);
    read_all(buffered, text + 1, sizeof(text) - 1, 31);
    CHECK(parse(text).start == member.start);
    CHECK(read(unread, text, sizeof(text)) == -1 && errno == ESRCH);
    CHECK(lseek(buffered, 0, SEEK_SET) == 0 && read(buffered, text, 1) == -1 && errno == ESRCH);
    CHECK(stat_file(getpid(), tid) == -1 && errno == ENOENT);
    close(buffered);
    close(unread);
    for (unsigned i = 0; i < 2; i++) {
        close(ready[i]);
        close(finish[i]);
    }
    observed("thread_birth_direct_tid_and_retained_snapshot_are_independent");
    exec_control(0);
    observed("leader_exec_preserves_process_boot_and_start_ticks");
    exec_control(1);
    observed("nonleader_exec_preserves_process_boot_and_start_ticks");

    pid_t previous = 0;
    for (unsigned i = 0; i < 256; i++) {
        CHECK(pipe(finish) == 0);
        child = fork();
        CHECK(child >= 0);
        if (!child) {
            close(finish[1]);
            byte(finish[0], 0);
            _exit(0);
        }
        close(finish[0]);
        born = identity(child, 0);
        CHECK(born.pid == child && child != previous && born.start <= now_ticks());
        previous = child;
        byte(finish[1], 1);
        reap(child);
        CHECK(close(finish[1]) == 0);
    }
    observed("256_task_slot_recycles_keep_current_pid_and_creation_time");
    CHECK(observations == 7);
    puts("PROC_IDENTITY_PASS observations=7");
    return 0;
}
