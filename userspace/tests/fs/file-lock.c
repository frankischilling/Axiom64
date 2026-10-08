// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef LOCK_LINKAGE
#define LOCK_LINKAGE "static"
#endif
#define CHECK(expression)                                                                          \
    do {                                                                                           \
        if (!(expression)) {                                                                       \
            fprintf(stderr, "FILE_LOCK_FAIL line=%d expression=%s errno=%d\n", __LINE__,           \
                    #expression, errno);                                                           \
            _exit(1);                                                                              \
        }                                                                                          \
    } while (0)

static char path[1024], other[1024];
_Static_assert(ATOMIC_INT_LOCK_FREE == 2, "signal flag requires lock-free integer atomics");
static atomic_int caught;

static int open_file(const char* name, int flags) {
    int fd = open(name, flags | O_CREAT, 0600);
    CHECK(fd >= 0);
    return fd;
}

static void conflict(int fd, int mode) {
    errno = 0;
    CHECK(flock(fd, mode | LOCK_NB) == -1 && errno == EWOULDBLOCK);
}

static void wait_child(pid_t child) {
    int status;
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

static void modes(void) {
    int first = open_file(path, O_RDONLY), second = open_file(path, O_WRONLY);
    int third = open_file(path, O_RDWR), duplicate = dup(first);
    CHECK(duplicate >= 0 && flock(first, LOCK_EX) == 0 && flock(duplicate, LOCK_EX) == 0);
    conflict(second, LOCK_EX);
    conflict(third, LOCK_SH);
    CHECK(write(second, "advisory", 8) == 8);
    char bytes[8];
    CHECK(read(first, bytes, sizeof(bytes)) == 8 && !memcmp(bytes, "advisory", 8));
    CHECK(close(first) == 0);
    conflict(second, LOCK_EX);
    CHECK(flock(duplicate, LOCK_UN | LOCK_NB) == 0 && flock(duplicate, LOCK_UN) == 0);
    CHECK(flock(duplicate, LOCK_SH) == 0 && flock(second, LOCK_SH) == 0);
    conflict(duplicate, LOCK_EX); // A failed conversion releases this description's shared lock.
    CHECK(flock(second, LOCK_UN) == 0 && flock(third, LOCK_EX | LOCK_NB) == 0);
    conflict(duplicate, LOCK_SH);
    CHECK(flock(third, LOCK_SH) == 0 && flock(duplicate, LOCK_SH | LOCK_NB) == 0);
    CHECK(close(duplicate) == 0 && close(second) == 0 && close(third) == 0);
    const int invalid[] = {0, LOCK_SH | LOCK_EX, LOCK_SH | LOCK_UN, 64, 128, 256};
    for (unsigned i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i) {
        errno = 0;
        CHECK(flock(-1, invalid[i]) == -1 && errno == EINVAL);
    }
    CHECK(flock(-1, LOCK_EX) == -1 && errno == EBADF);
    printf("FILE_LOCK_MODES_PASS conversion_advisory_errors\n");
}

static void aliases(const char* directory) {
    char hard[1024], symbolic[1024], renamed[1024];
    CHECK(snprintf(hard, sizeof(hard), "%s/hard", directory) > 0);
    CHECK(snprintf(symbolic, sizeof(symbolic), "%s/symbolic", directory) > 0);
    CHECK(snprintf(renamed, sizeof(renamed), "%s/renamed", directory) > 0);
    int owner = open_file(path, O_RDWR);
    CHECK(flock(owner, LOCK_EX) == 0 && link(path, hard) == 0 && symlink(path, symbolic) == 0);
    int linked = open_file(hard, O_RDONLY), followed = open_file(symbolic, O_RDONLY);
    conflict(linked, LOCK_EX);
    conflict(followed, LOCK_SH);
    CHECK(rename(path, renamed) == 0);
    int moved = open_file(renamed, O_RDONLY);
    conflict(moved, LOCK_EX);
    CHECK(unlink(hard) == 0 && unlink(symbolic) == 0 && unlink(renamed) == 0);
    int replacement = open_file(path, O_RDWR);
    CHECK(flock(replacement, LOCK_EX | LOCK_NB) == 0);
    conflict(moved, LOCK_EX);
    CHECK(close(owner) == 0 && flock(moved, LOCK_EX | LOCK_NB) == 0);
    CHECK(close(linked) == 0 && close(followed) == 0 && close(moved) == 0);
    CHECK(close(replacement) == 0);
    int first = open(directory, O_RDONLY | O_DIRECTORY), second = open(directory, O_RDONLY);
    CHECK(first >= 0 && second >= 0 && flock(first, LOCK_EX) == 0);
    conflict(second, LOCK_EX);
    CHECK(close(first) == 0 && flock(second, LOCK_EX | LOCK_NB) == 0 && close(second) == 0);
    printf("FILE_LOCK_INODE_PASS hardlink_symlink_rename_unlink_directory\n");
}

static void inherited(const char* executable, int cloexec) {
    int owner = open_file(path, O_RDONLY | (cloexec ? O_CLOEXEC : 0)), barrier[2];
    CHECK(flock(owner, LOCK_EX) == 0 && pipe(barrier) == 0);
    pid_t child = fork();
    CHECK(child >= 0);
    if (!child) {
        CHECK(close(barrier[1]) == 0);
        char byte;
        CHECK(read(barrier[0], &byte, 1) == 1 && close(barrier[0]) == 0);
        CHECK(flock(owner, LOCK_EX | LOCK_NB) == 0);
        char descriptor[32];
        snprintf(descriptor, sizeof(descriptor), "%d", owner);
        execl(executable, executable, "--exec", descriptor, path, cloexec ? "close" : "keep",
              (char*)0);
        CHECK(0);
    }
    CHECK(close(owner) == 0 && close(barrier[0]) == 0);
    int probe = open_file(path, O_RDONLY);
    conflict(probe, LOCK_EX); // Only the forked child now retains the description.
    CHECK(write(barrier[1], "g", 1) == 1 && close(barrier[1]) == 0);
    wait_child(child);
    CHECK(flock(probe, LOCK_EX | LOCK_NB) == 0 && close(probe) == 0);
}

struct Operation {
    int fd, mode, result, error;
    atomic_int entered, done;
};

static void* worker(void* pointer) {
    struct Operation* operation = pointer;
    atomic_store(&operation->entered, 1);
    operation->result = flock(operation->fd, operation->mode);
    operation->error = errno;
    atomic_store(&operation->done, 1);
    return 0;
}

static void await_entry(struct Operation* operation) {
    while (!atomic_load(&operation->entered))
        sched_yield();
    usleep(40000);
    CHECK(!atomic_load(&operation->done));
}

static void blocked_reuse(int replace, int nonblocking) {
    int owner = open_file(path, O_RDONLY), original = open_file(path, O_RDONLY);
    int replacement_owner = open_file(other, O_RDONLY);
    CHECK(flock(owner, LOCK_EX) == 0 && flock(replacement_owner, LOCK_EX) == 0);
    if (nonblocking)
        CHECK(fcntl(original, F_SETFL, O_NONBLOCK) == 0);
    struct Operation operation = {.fd = original, .mode = LOCK_EX};
    pthread_t thread;
    CHECK(pthread_create(&thread, 0, worker, &operation) == 0);
    await_entry(&operation);
    int replacement;
    if (replace) {
        replacement = open_file(other, O_RDONLY);
        CHECK(dup2(replacement, original) == original && close(replacement) == 0);
        replacement = original;
    } else {
        CHECK(close(original) == 0);
        replacement = open_file(other, O_RDONLY);
        CHECK(replacement == original);
    }
    CHECK(flock(owner, LOCK_UN) == 0 && pthread_join(thread, 0) == 0 && operation.result == 0);
    CHECK(flock(owner, LOCK_EX | LOCK_NB) == 0); // The captured description's last ref ended.
    conflict(replacement, LOCK_EX); // The replacement description was never used by the wait.
    CHECK(close(owner) == 0 && close(replacement) == 0 && close(replacement_owner) == 0);
}

static void handler(int number) {
    (void)number;
    atomic_fetch_add(&caught, 1);
}

static void interrupted(int restart) {
    struct sigaction action = {.sa_handler = handler, .sa_flags = restart ? SA_RESTART : 0};
    sigemptyset(&action.sa_mask);
    CHECK(sigaction(SIGUSR1, &action, 0) == 0);
    atomic_store(&caught, 0);
    int owner = open_file(path, O_RDONLY), original = open_file(path, O_RDONLY);
    int replacement_owner = open_file(other, O_RDONLY), replacement = open_file(other, O_RDONLY);
    CHECK(flock(owner, LOCK_EX) == 0 && flock(replacement_owner, LOCK_EX) == 0);
    struct Operation operation = {.fd = original, .mode = LOCK_EX};
    pthread_t thread;
    CHECK(pthread_create(&thread, 0, worker, &operation) == 0);
    await_entry(&operation);
    CHECK(dup2(replacement, original) == original);
    CHECK(pthread_kill(thread, SIGUSR1) == 0);
    while (!atomic_load(&caught))
        usleep(10000);
    if (restart) {
        usleep(40000);
        CHECK(!atomic_load(&operation.done) && flock(owner, LOCK_UN) == 0);
        usleep(40000);
        CHECK(!atomic_load(&operation.done)); // Restart performs a fresh lookup of the reused fd.
        CHECK(flock(replacement_owner, LOCK_UN) == 0);
    }
    CHECK(pthread_join(thread, 0) == 0);
    CHECK(restart ? operation.result == 0 : operation.result == -1 && operation.error == EINTR);
    CHECK(flock(owner, LOCK_EX | LOCK_NB) == 0);
    CHECK(close(owner) == 0 && close(original) == 0 && close(replacement) == 0);
    CHECK(close(replacement_owner) == 0);
}

static void stopped(void) {
    int owner = open_file(path, O_RDONLY), other_owner = open_file(other, O_RDONLY);
    int ready[2], complete[2];
    CHECK(flock(owner, LOCK_EX) == 0 && flock(other_owner, LOCK_EX) == 0);
    CHECK(pipe(ready) == 0 && pipe(complete) == 0);
    pid_t child = fork();
    CHECK(child >= 0);
    if (!child) {
        CHECK(close(owner) == 0 && close(other_owner) == 0);
        CHECK(close(ready[0]) == 0 && close(complete[0]) == 0);
        int original = open_file(path, O_RDONLY);
        struct Operation operation = {.fd = original, .mode = LOCK_EX};
        pthread_t thread;
        CHECK(pthread_create(&thread, 0, worker, &operation) == 0);
        await_entry(&operation);
        CHECK(close(original) == 0 && open_file(other, O_RDONLY) == original);
        CHECK(write(ready[1], "r", 1) == 1);
        CHECK(pthread_join(thread, 0) == 0 && operation.result == 0);
        CHECK(write(complete[1], "d", 1) == 1 && close(original) == 0);
        _exit(0);
    }
    CHECK(close(ready[1]) == 0 && close(complete[1]) == 0);
    char byte;
    CHECK(read(ready[0], &byte, 1) == 1 && kill(child, SIGSTOP) == 0);
    int status;
    CHECK(waitpid(child, &status, WUNTRACED) == child && WIFSTOPPED(status));
    CHECK(flock(owner, LOCK_UN) == 0 && kill(child, SIGCONT) == 0);
    struct pollfd descriptor = {.fd = complete[0], .events = POLLIN};
    CHECK(poll(&descriptor, 1, 100) == 0);
    CHECK(flock(other_owner, LOCK_UN) == 0 && read(complete[0], &byte, 1) == 1);
    wait_child(child);
    CHECK(close(owner) == 0 && close(other_owner) == 0);
    CHECK(close(ready[0]) == 0 && close(complete[0]) == 0);
    printf("FILE_LOCK_STOP_PASS fresh_lookup_after_continue\n");
}

static void teardown(const char* executable, int terminate) {
    int owner = open_file(path, O_RDONLY), probe = open_file(other, O_RDONLY), ready[2];
    CHECK(flock(owner, LOCK_EX) == 0 && pipe(ready) == 0);
    pid_t child = fork();
    CHECK(child >= 0);
    if (!child) {
        CHECK(close(owner) == 0 && close(probe) == 0 && close(ready[0]) == 0);
        int held = open_file(other, O_RDONLY | O_CLOEXEC), original = open_file(path, O_RDONLY);
        CHECK(flock(held, LOCK_EX) == 0);
        struct Operation operation = {.fd = original, .mode = LOCK_EX};
        pthread_t thread;
        CHECK(pthread_create(&thread, 0, worker, &operation) == 0);
        await_entry(&operation);
        CHECK(close(original) == 0 && write(ready[1], "r", 1) == 1);
        if (terminate == 1) {
            for (;;)
                pause();
        }
        if (terminate == 2) {
            execl(executable, executable, "--exec-marker", (char*)0);
            CHECK(0);
        }
        _exit(0);
    }
    CHECK(close(ready[1]) == 0);
    char byte;
    CHECK(read(ready[0], &byte, 1) == 1);
    if (terminate == 1) {
        CHECK(kill(child, SIGKILL) == 0);
        int status;
        CHECK(waitpid(child, &status, 0) == child && WIFSIGNALED(status) &&
              WTERMSIG(status) == SIGKILL);
    } else
        wait_child(child);
    CHECK(flock(probe, LOCK_EX | LOCK_NB) == 0);
    CHECK(flock(owner, LOCK_UN) == 0 && flock(owner, LOCK_EX | LOCK_NB) == 0);
    CHECK(close(owner) == 0 && close(probe) == 0 && close(ready[0]) == 0);
}

static void contention(void) {
    int descriptor = open_file(path, O_RDWR), ready[2], go[2];
    uint32_t value = 0;
    CHECK(ftruncate(descriptor, 0) == 0 &&
          write(descriptor, &value, sizeof(value)) == sizeof(value));
    CHECK(pipe(ready) == 0 && pipe(go) == 0);
    pid_t children[8];
    for (unsigned i = 0; i < 8; ++i) {
        children[i] = fork();
        CHECK(children[i] >= 0);
        if (!children[i]) {
            CHECK(close(descriptor) == 0 && close(ready[0]) == 0 && close(go[1]) == 0);
            int independent = open_file(path, O_RDWR);
            CHECK(write(ready[1], "r", 1) == 1);
            char byte;
            CHECK(read(go[0], &byte, 1) == 1);
            for (unsigned update = 0; update < 32; ++update) {
                CHECK(flock(independent, LOCK_EX) == 0 && lseek(independent, 0, SEEK_SET) == 0);
                CHECK(read(independent, &value, sizeof(value)) == sizeof(value));
                sched_yield(); // Other independent descriptions must wait throughout the update.
                ++value;
                CHECK(lseek(independent, 0, SEEK_SET) == 0);
                CHECK(write(independent, &value, sizeof(value)) == sizeof(value));
                CHECK(flock(independent, LOCK_UN) == 0);
            }
            CHECK(close(independent) == 0);
            _exit(0);
        }
    }
    CHECK(close(ready[1]) == 0 && close(go[0]) == 0);
    char byte;
    for (unsigned i = 0; i < 8; ++i)
        CHECK(read(ready[0], &byte, 1) == 1);
    CHECK(write(go[1], "gggggggg", 8) == 8);
    for (unsigned i = 0; i < 8; ++i)
        wait_child(children[i]);
    CHECK(lseek(descriptor, 0, SEEK_SET) == 0 &&
          read(descriptor, &value, sizeof(value)) == sizeof(value));
    CHECK(value == 256 && close(descriptor) == 0 && close(ready[0]) == 0 && close(go[1]) == 0);
    printf("FILE_LOCK_CONTENTION_PASS processes=8 updates=256 yield_while_locked\n");
}

static uint32_t random_word(uint32_t* state) {
    *state ^= *state << 13;
    *state ^= *state >> 17;
    *state ^= *state << 5;
    return *state;
}

static void trace(const char* directory) {
    char names[4][1024];
    int descriptors[12];
    for (unsigned i = 0; i < 4; ++i)
        CHECK(snprintf(names[i], sizeof(names[i]), "%s/trace-%u", directory, i) > 0);
    for (unsigned i = 0; i < 12; ++i)
        descriptors[i] = open_file(names[i % 4], O_RDONLY);
    const int operations[] = {LOCK_SH | LOCK_NB, LOCK_EX | LOCK_NB, LOCK_UN | LOCK_NB, 0, 3, 64};
    uint32_t state = 0x29483951, digest = 2166136261U;
    for (unsigned i = 0; i < 4096; ++i) {
        uint32_t choice = random_word(&state);
        unsigned target = choice % 12;
        int result, error = 0;
        if (!(choice & 15)) {
            unsigned source = (choice >> 8) % 12;
            CHECK(dup2(descriptors[source], descriptors[target]) == descriptors[target]);
            result = 0;
        } else if ((choice & 15) == 1) {
            CHECK(close(descriptors[target]) == 0);
            descriptors[target] = open_file(names[(choice >> 8) % 4], O_RDONLY);
            result = 0;
        } else {
            errno = 0;
            result = flock(descriptors[target], operations[(choice >> 8) % 6]);
            error = result ? errno : 0;
            CHECK(result == 0 || (result == -1 && (error == EWOULDBLOCK || error == EINVAL)));
        }
        digest = (digest ^ choice) * 16777619U;
        digest = (digest ^ (uint32_t)result) * 16777619U;
        digest = (digest ^ (uint32_t)error) * 16777619U;
    }
    for (unsigned i = 0; i < 12; ++i)
        CHECK(close(descriptors[i]) == 0);
    for (unsigned i = 0; i < 4; ++i)
        CHECK(unlink(names[i]) == 0);
    printf("FILE_LOCK_TRACE_PASS operations=4096 digest=%08x\n", digest);
}

static void unsupported(void) {
    int endpoints[2];
    CHECK(pipe(endpoints) == 0);
    CHECK(flock(endpoints[0], LOCK_EX | LOCK_NB) == -1 && errno == EOPNOTSUPP);
    CHECK(close(endpoints[0]) == 0 && close(endpoints[1]) == 0);
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, endpoints) == 0);
    CHECK(flock(endpoints[0], LOCK_SH | LOCK_NB) == -1 && errno == EOPNOTSUPP);
    CHECK(close(endpoints[0]) == 0 && close(endpoints[1]) == 0);
    int event = epoll_create1(0);
    CHECK(event >= 0 && flock(event, LOCK_UN) == -1 && errno == EOPNOTSUPP && close(event) == 0);
    int owner = open_file(path, O_RDONLY);
    CHECK(flock(owner, 16) == -1 && errno == EINVAL && close(owner) == 0);
    int path_only = open(path, O_PATH);
    CHECK(path_only >= 0 && flock(path_only, LOCK_EX) == -1 && errno == EBADF);
    CHECK(close(path_only) == 0);
    printf("FILE_LOCK_UNSUPPORTED_PASS anonymous=3 mandatory=EINVAL opath=EBADF\n");
}

static void readonly(const char* name) {
    int owner = open(name, O_RDONLY), probe = open(name, O_RDONLY);
    CHECK(owner >= 0 && probe >= 0 && flock(owner, LOCK_EX | LOCK_NB) == 0);
    conflict(probe, LOCK_EX);
    CHECK(close(owner) == 0 && flock(probe, LOCK_EX | LOCK_NB) == 0 && close(probe) == 0);
    printf("FILE_LOCK_READONLY_MOUNT_PASS linkage=%s\n", LOCK_LINKAGE);
}

int main(int argc, char** argv) {
    setvbuf(stdout, 0, _IONBF, 0);
    if (argc == 2 && !strcmp(argv[1], "--exec-marker"))
        return 0;
    if (argc == 3 && !strcmp(argv[1], "--readonly")) {
        readonly(argv[2]);
        return 0;
    }
    if (argc == 5 && !strcmp(argv[1], "--exec")) {
        int owner = atoi(argv[2]);
        int keep = !strcmp(argv[4], "keep");
        if (keep)
            CHECK(fcntl(owner, F_GETFD) >= 0);
        else
            CHECK(fcntl(owner, F_GETFD) == -1 && errno == EBADF);
        int probe = open_file(argv[3], O_RDONLY);
        if (keep) {
            conflict(probe, LOCK_EX);
            CHECK(flock(owner, LOCK_UN) == 0 && close(owner) == 0);
        }
        CHECK(flock(probe, LOCK_EX | LOCK_NB) == 0 && close(probe) == 0);
        return 0;
    }
    int guest = argc == 3 && !strcmp(argv[2], "--guest");
    CHECK((argc == 2 || guest) && strlen(argv[1]) < 950);
    const char* directory = argv[1];
    CHECK(mkdir(directory, 0700) == 0);
    CHECK(snprintf(path, sizeof(path), "%s/lock", directory) > 0);
    CHECK(snprintf(other, sizeof(other), "%s/other", directory) > 0);
    modes();
    aliases(directory);
    inherited(argv[0], 0);
    inherited(argv[0], 1);
    printf("FILE_LOCK_INHERITANCE_PASS fork_exec_cloexec_last_close\n");
    for (unsigned i = 0; i < 48; ++i)
        blocked_reuse(i & 1, i & 2);
    printf("FILE_LOCK_RETAINED_WAIT_PASS cycles=48 close_dup2_nonblock\n");
    interrupted(0);
    interrupted(1);
    printf("FILE_LOCK_SIGNALS_PASS interrupted_restart_fd_lookup\n");
    stopped();
    teardown(argv[0], 0);
    teardown(argv[0], 1);
    teardown(argv[0], 2);
    printf("FILE_LOCK_TEARDOWN_PASS exit_group_kill_exec\n");
    contention();
    trace(directory);
    if (guest)
        unsupported();
    CHECK(unlink(path) == 0 && unlink(other) == 0 && rmdir(directory) == 0);
    printf("FILE_LOCK_TESTS_PASS linkage=%s\n", LOCK_LINKAGE);
    return 0;
}
