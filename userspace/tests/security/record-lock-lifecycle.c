// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define CHECK(expression)                                                                          \
    do {                                                                                           \
        if (!(expression)) {                                                                       \
            dprintf(2, "RECORD_LIFECYCLE_FAIL line=%d errno=%d expression=%s\n", __LINE__, errno,  \
                    #expression);                                                                  \
            _exit(1);                                                                              \
        }                                                                                          \
    } while (0)

static unsigned observations;
static int notification = -1;
static volatile sig_atomic_t caught;

static void observed(const char* name) {
    printf("RECORD_LIFECYCLE_OBSERVATION %s\n", name);
    fflush(stdout);
    observations++;
}

static void transfer(int fd, void* bytes, size_t size, int writing) {
    for (size_t done = 0; done < size;) {
        ssize_t count = writing ? write(fd, (char*)bytes + done, size - done)
                                : read(fd, (char*)bytes + done, size - done);
        if (count < 0 && errno == EINTR)
            continue;
        CHECK(count > 0);
        done += (size_t)count;
    }
}

static void byte(int fd, int writing) {
    char value = 'x';
    transfer(fd, &value, 1, writing);
    CHECK(value == 'x');
}

static struct flock region(short type, off_t first, off_t length) {
    return (struct flock){.l_type = type, .l_whence = SEEK_SET, .l_start = first, .l_len = length};
}

static void set(int fd, int command, short type, off_t first, off_t length) {
    struct flock lock = region(type, first, length);
    CHECK(fcntl(fd, command, &lock) == 0);
}

static void query(int fd, off_t first, short type, off_t length, pid_t pid) {
    struct flock lock = region(F_WRLCK, first, 1);
    CHECK(fcntl(fd, F_GETLK, &lock) == 0 && lock.l_type == type);
    if (type != F_UNLCK)
        CHECK(lock.l_start == first && lock.l_len == length && lock.l_pid == pid);
}

static void reap(pid_t child) {
    int status;
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

static int64_t now(void) {
    struct timespec value;
    CHECK(clock_gettime(CLOCK_MONOTONIC, &value) == 0);
    return (int64_t)value.tv_sec * 1000000000 + value.tv_nsec;
}

static char state(pid_t process, pid_t thread) {
    char path[128], text[4096];
    snprintf(path, sizeof(path), "/proc/%d/task/%d/status", process, thread);
    int fd = open(path, O_RDONLY);
    CHECK(fd >= 0);
    ssize_t size = read(fd, text, sizeof(text) - 1);
    CHECK(size > 0);
    close(fd);
    text[size] = 0;
    char* field = strstr(text, "\nState:\t");
    CHECK(field);
    return field[8];
}

static void blocked(pid_t process, pid_t thread) {
    int64_t deadline = now() + 5000000000;
    while (state(process, thread) != 'S') {
        CHECK(now() < deadline);
        sched_yield();
    }
    // The ready write is followed directly by fcntl, with no intervening wait.
    // An observed sleeping state therefore establishes the actual lock wait.
    printf("RECORD_LIFECYCLE_BLOCKED pid=%d tid=%d\n", process, thread);
    fflush(stdout);
}

static void signal_handler(int signal) {
    (void)signal;
    caught = 1;
    if (notification >= 0) {
        char value = 'x';
        if (write(notification, &value, 1) != 1)
            _exit(2);
    }
}

static void circular(int file, unsigned members) {
    int ready[2], answer[2], gates[3][2];
    CHECK(pipe(ready) == 0 && pipe(answer) == 0);
    pid_t children[3];
    for (unsigned i = 0; i < members; i++)
        CHECK(pipe(gates[i]) == 0);
    for (unsigned i = 0; i < members; i++) {
        children[i] = fork();
        CHECK(children[i] >= 0);
        if (!children[i]) {
            close(ready[0]);
            close(answer[0]);
            for (unsigned j = 0; j < members; j++) {
                close(gates[j][1]);
                if (j != i)
                    close(gates[j][0]);
            }
            set(file, F_SETLK, F_WRLCK, 10 * i, 1);
            byte(ready[1], 1);
            byte(gates[i][0], 0);
            struct flock lock = region(F_WRLCK, 10 * ((i + 1) % members), 1);
            int result = fcntl(file, F_SETLKW, &lock);
            int error = result < 0 ? errno : 0;
            CHECK(!result || (result == -1 && error == EDEADLK));
            transfer(answer[1], &error, sizeof(error), 1);
            set(file, F_SETLK, F_UNLCK, 0, 0);
            _exit(0);
        }
    }
    close(ready[1]);
    close(answer[1]);
    for (unsigned i = 0; i < members; i++) {
        close(gates[i][0]);
        byte(ready[0], 0);
    }
    // Establish each earlier edge before the last edge closes the cycle.
    for (unsigned i = 0; i + 1 < members; i++) {
        byte(gates[i][1], 1);
        blocked(children[i], children[i]);
    }
    byte(gates[members - 1][1], 1);
    unsigned deadlocks = 0;
    for (unsigned i = 0; i < members; i++) {
        int error;
        transfer(answer[0], &error, sizeof(error), 0);
        deadlocks += error == EDEADLK;
        close(gates[i][1]);
        reap(children[i]);
    }
    CHECK(deadlocks == 1);
    close(ready[0]);
    close(answer[0]);
    observed(members == 2 ? "two_process_posix_deadlock" : "three_process_posix_deadlock");
}

struct waiter {
    int fd, command, ready, result, error;
    pid_t thread;
};

static void* wait_thread(void* opaque) {
    struct waiter* wait = opaque;
    wait->thread = (pid_t)syscall(SYS_gettid);
    struct flock lock = region(F_WRLCK, 0, 1);
    transfer(wait->ready, &wait->thread, sizeof(wait->thread), 1);
    wait->result = fcntl(wait->fd, wait->command, &lock);
    wait->error = wait->result < 0 ? errno : 0;
    return NULL;
}

static void reuse(const char* path, const char* other, int ofd, int restart, int close_only) {
    int owner = open(path, O_RDWR), target = open(path, O_RDWR), keep = dup(target);
    int replacement = open(other, O_RDWR), probe = open(path, O_RDWR), channels[2], signals[2];
    CHECK(owner >= 0 && target >= 0 && keep >= 0 && replacement >= 0 && probe >= 0);
    CHECK(pipe(channels) == 0 && pipe(signals) == 0);
    set(owner, F_OFD_SETLK, F_WRLCK, 0, 1);
    set(replacement, F_OFD_SETLK, F_WRLCK, 0, 1);
    struct sigaction action = {.sa_handler = signal_handler, .sa_flags = restart ? SA_RESTART : 0};
    CHECK(sigaction(SIGUSR1, &action, NULL) == 0);
    caught = 0;
    notification = signals[1];
    struct waiter wait = {target, ofd ? F_OFD_SETLKW : F_SETLKW, channels[1], 0, 0, 0};
    pthread_t thread;
    CHECK(pthread_create(&thread, NULL, wait_thread, &wait) == 0);
    pid_t tid;
    transfer(channels[0], &tid, sizeof(tid), 0);
    blocked(getpid(), tid);
    if (close_only)
        CHECK(close(target) == 0);
    else {
        int newly_opened = open(other, O_RDWR);
        CHECK(newly_opened >= 0 && dup2(newly_opened, target) == target);
        close(newly_opened);
    }
    if (restart) {
        CHECK(pthread_kill(thread, SIGUSR1) == 0);
        byte(signals[0], 0);
        blocked(getpid(), tid);
    }
    set(owner, F_OFD_SETLK, F_UNLCK, 0, 0);
    if (restart) {
        // The restarted call now waits on the replacement inode, even after
        // the original owner unlocks. Its original description stays unlocked.
        blocked(getpid(), tid);
        query(probe, 0, F_UNLCK, 0, 0);
        set(replacement, F_OFD_SETLK, F_UNLCK, 0, 0);
    }
    CHECK(pthread_join(thread, NULL) == 0);
    printf("RECORD_LIFECYCLE_WAIT_RESULT ofd=%d restart=%d result=%d error=%d\n", ofd, restart,
           wait.result, wait.error);
    fflush(stdout);
    CHECK((!ofd && !restart ? wait.result == -1 && wait.error == EBADF : wait.result == 0) &&
          (!restart || caught));
    if (restart) {
        int external = open(other, O_RDWR);
        CHECK(external >= 0);
        if (ofd)
            query(external, 0, F_WRLCK, 1, -1);
        else {
            pid_t child = fork();
            CHECK(child >= 0);
            if (!child) {
                query(external, 0, F_WRLCK, 1, getppid());
                _exit(0);
            }
            reap(child);
        }
        close(external);
    } else {
        query(probe, 0, ofd ? F_WRLCK : F_UNLCK, ofd ? 1 : 0, ofd ? -1 : 0);
        int external = open(other, O_RDWR);
        CHECK(external >= 0);
        query(external, 0, F_WRLCK, 1, -1);
        close(external);
    }
    notification = -1;
    close(channels[0]);
    close(channels[1]);
    close(signals[0]);
    close(signals[1]);
    close(keep);
    if (!close_only)
        close(target);
    close(owner);
    close(replacement);
    close(probe);
    observed(close_only ? (ofd ? "ofd_wait_retains_closed_description"
                               : "posix_wait_closed_descriptor_returns_ebadf")
             : restart  ? (ofd ? "ofd_restart_selects_replaced_descriptor"
                               : "posix_restart_selects_replaced_descriptor")
                        : (ofd ? "ofd_wait_retains_original_description"
                               : "posix_wait_replaced_descriptor_returns_ebadf"));
}

static void signals(const char* path, int stop, int fatal) {
    int owner = open(path, O_RDWR), ready[2], done[2];
    CHECK(owner >= 0 && pipe(ready) == 0 && pipe(done) == 0);
    set(owner, F_OFD_SETLK, F_WRLCK, 0, 1);
    pid_t child = fork();
    CHECK(child >= 0);
    if (!child) {
        close(owner);
        close(ready[0]);
        close(done[0]);
        int fd = open(path, O_RDWR);
        CHECK(fd >= 0);
        if (fatal)
            set(fd, F_SETLK, F_WRLCK, 4, 1);
        caught = 0;
        struct sigaction action = {.sa_handler = signal_handler};
        CHECK(sigaction(SIGUSR1, &action, NULL) == 0);
        struct flock lock = region(F_WRLCK, 0, 1);
        byte(ready[1], 1);
        int result = fcntl(fd, F_OFD_SETLKW, &lock);
        if (stop)
            CHECK(result == 0);
        else
            CHECK(result == -1 && errno == EINTR && caught);
        byte(done[1], 1);
        _exit(0);
    }
    close(ready[1]);
    close(done[1]);
    byte(ready[0], 0);
    blocked(child, child);
    if (fatal) {
        query(owner, 4, F_WRLCK, 1, child);
        CHECK(kill(child, SIGKILL) == 0);
        int status;
        CHECK(waitpid(child, &status, 0) == child && WIFSIGNALED(status) &&
              WTERMSIG(status) == SIGKILL);
        query(owner, 4, F_UNLCK, 0, 0);
    } else if (stop) {
        CHECK(kill(child, SIGSTOP) == 0);
        int status;
        CHECK(waitpid(child, &status, WUNTRACED) == child && WIFSTOPPED(status));
        CHECK(state(child, child) == 'T' && kill(child, SIGCONT) == 0);
        blocked(child, child);
        set(owner, F_OFD_SETLK, F_UNLCK, 0, 0);
        byte(done[0], 0);
        reap(child);
    } else {
        CHECK(kill(child, SIGUSR1) == 0);
        byte(done[0], 0);
        reap(child);
    }
    set(owner, F_OFD_SETLK, F_UNLCK, 0, 0);
    close(owner);
    close(ready[0]);
    close(done[0]);
    observed(fatal  ? "fatal_waiter_exit_releases_owned_ranges"
             : stop ? "ofd_stop_continue_reenters_wait"
                    : "ofd_caught_signal_returns_eintr");
}

static void exec_wait(const char* path, const char* observer) {
    int owner = open(path, O_RDWR), ready[2], go[2], after[2], finish[2];
    CHECK(owner >= 0 && pipe(ready) == 0 && pipe(go) == 0 && pipe(after) == 0 && pipe(finish) == 0);
    set(owner, F_OFD_SETLK, F_WRLCK, 0, 1);
    pid_t child = fork();
    CHECK(child >= 0);
    if (!child) {
        close(owner);
        close(ready[0]);
        close(go[1]);
        close(after[0]);
        close(finish[1]);
        int fd = open(path, O_RDWR | O_CLOEXEC);
        CHECK(fd >= 0);
        set(fd, F_SETLK, F_WRLCK, 4, 1);
        set(fd, F_OFD_SETLK, F_WRLCK, 8, 1);
        struct waiter wait = {fd, F_OFD_SETLKW, ready[1], 0, 0, 0};
        pthread_t thread;
        CHECK(pthread_create(&thread, NULL, wait_thread, &wait) == 0);
        byte(go[0], 0);
        char start[32], end[32];
        snprintf(start, sizeof(start), "%d", after[1]);
        snprintf(end, sizeof(end), "%d", finish[0]);
        execl(observer, observer, "--exec", start, end, NULL);
        CHECK(0);
    }
    close(ready[1]);
    close(go[0]);
    close(after[1]);
    close(finish[0]);
    pid_t tid;
    transfer(ready[0], &tid, sizeof(tid), 0);
    blocked(child, tid);
    query(owner, 4, F_WRLCK, 1, child);
    query(owner, 8, F_WRLCK, 1, -1);
    byte(go[1], 1);
    byte(after[0], 0);
    query(owner, 4, F_UNLCK, 0, 0);
    query(owner, 8, F_UNLCK, 0, 0);
    set(owner, F_OFD_SETLK, F_UNLCK, 0, 0);
    byte(finish[1], 1);
    reap(child);
    close(owner);
    close(ready[0]);
    close(go[1]);
    close(after[0]);
    close(finish[1]);
    observed("exec_retires_blocked_sibling_and_cloexec_lock_owners");
}

static void canonical(const char* path, const char* alias) {
    CHECK(link(path, alias) == 0);
    int file = open(path, O_RDWR), old = open(alias, O_RDWR);
    CHECK(file >= 0 && old >= 0);
    struct stat first, second;
    CHECK(fstat(file, &first) == 0 && fstat(old, &second) == 0 && first.st_ino == second.st_ino);
    set(file, F_OFD_SETLK, F_WRLCK, 0, 1);
    query(old, 0, F_WRLCK, 1, -1);
    CHECK(unlink(path) == 0 && unlink(alias) == 0);
    int replacement = open(path, O_RDWR | O_CREAT | O_EXCL, 0644);
    CHECK(replacement >= 0 && fstat(replacement, &second) == 0 && first.st_ino != second.st_ino);
    query(old, 0, F_WRLCK, 1, -1);
    query(replacement, 0, F_UNLCK, 0, 0);
    CHECK(pwrite(file, "old", 3, 0) == 3 && pwrite(replacement, "new", 3, 0) == 3);
    char data[3];
    CHECK(pread(old, data, 3, 0) == 3 && !memcmp(data, "old", 3));
    close(file);
    query(old, 0, F_UNLCK, 0, 0);
    close(old);
    CHECK(fsync(replacement) == 0);
    close(replacement);
    observed("hardlink_unlinked_inode_and_replacement_keep_distinct_ownership");
}

static void range_atomicity(const char* path, int quota) {
    int file = open(path, O_RDWR), external = open(path, O_RDWR);
    CHECK(file >= 0 && external >= 0);
    set(file, F_OFD_SETLK, F_WRLCK, 0, 3);
    struct flock invalid = region(F_UNLCK, INT64_MAX, 2);
    CHECK(fcntl(file, F_OFD_SETLK, &invalid) == -1 && errno == EOVERFLOW);
    query(external, 0, F_WRLCK, 3, -1);
    invalid = region(F_UNLCK, -1, 1);
    CHECK(fcntl(file, F_OFD_SETLK, &invalid) == -1 && errno == EINVAL);
    query(external, 0, F_WRLCK, 3, -1);
    observed("invalid_and_overflow_ranges_leave_ownership_unchanged");
    if (quota) {
        for (unsigned i = 1; i < 2048; i++)
            set(file, F_OFD_SETLK, F_WRLCK, 10 + 2 * i, 1);
        invalid = region(F_WRLCK, 5000, 1);
        CHECK(fcntl(file, F_OFD_SETLK, &invalid) == -1 && errno == ENOLCK);
        query(external, 5000, F_UNLCK, 0, 0);
        invalid = region(F_UNLCK, 1, 1);
        CHECK(fcntl(file, F_OFD_SETLK, &invalid) == -1 && errno == ENOLCK);
        query(external, 0, F_WRLCK, 3, -1);
        for (unsigned i = 1; i < 2048; i++)
            query(external, 10 + 2 * i, F_WRLCK, 1, -1);
        set(file, F_OFD_SETLK, F_UNLCK, 12, 1);
        set(file, F_OFD_SETLK, F_UNLCK, 1, 1);
        query(external, 0, F_WRLCK, 1, -1);
        query(external, 1, F_UNLCK, 0, 0);
        query(external, 2, F_WRLCK, 1, -1);
        observed("guest_enolck_addition_and_split_fail_atomically");
    }
    set(file, F_OFD_SETLK, F_UNLCK, 0, 0);
    close(file);
    close(external);
}

int main(int argc, char** argv) {
    if (argc == 4 && !strcmp(argv[1], "--exec")) {
        byte(atoi(argv[2]), 1);
        byte(atoi(argv[3]), 0);
        return 0;
    }
    if (argc == 3 && !strcmp(argv[1], "--persist-check")) {
        char path[1024], data[3];
        CHECK(snprintf(path, sizeof(path), "%s/original", argv[2]) < (int)sizeof(path));
        int file = open(path, O_RDWR);
        CHECK(file >= 0 && pread(file, data, sizeof(data), 0) == 3 && !memcmp(data, "new", 3));
        query(file, 0, F_UNLCK, 0, 0);
        set(file, F_OFD_SETLK, F_WRLCK, 0, 1);
        close(file);
        puts("RECORD_LIFECYCLE_PERSIST_PASS bytes=new locks=absent");
        return 0;
    }
    CHECK(argc == 3 || (argc == 4 && !strcmp(argv[3], "--guest-quota")));
    CHECK(mkdir(argv[1], 0700) == 0);
    char path[1024], other[1024], alias[1024];
    CHECK(snprintf(path, sizeof(path), "%s/original", argv[1]) < (int)sizeof(path));
    CHECK(snprintf(other, sizeof(other), "%s/replacement", argv[1]) < (int)sizeof(other));
    CHECK(snprintf(alias, sizeof(alias), "%s/alias", argv[1]) < (int)sizeof(alias));
    int file = open(path, O_RDWR | O_CREAT | O_EXCL, 0644);
    int second = open(other, O_RDWR | O_CREAT | O_EXCL, 0644);
    CHECK(file >= 0 && second >= 0);
    circular(file, 2);
    circular(file, 3);
    close(file);
    close(second);
    reuse(path, other, 0, 0, 0);
    reuse(path, other, 1, 0, 0);
    reuse(path, other, 0, 0, 1);
    reuse(path, other, 1, 0, 1);
    reuse(path, other, 0, 1, 0);
    reuse(path, other, 1, 1, 0);
    signals(path, 0, 0);
    signals(path, 1, 0);
    signals(path, 0, 1);
    exec_wait(path, argv[2]);
    canonical(path, alias);
    range_atomicity(path, argc == 4);
    printf("RECORD_LIFECYCLE_PASS observations=%u quota=%d\n", observations, argc == 4);
    return 0;
}
