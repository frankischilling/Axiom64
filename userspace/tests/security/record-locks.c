// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHECK(expression)                                                                          \
    do {                                                                                           \
        if (!(expression)) {                                                                       \
            fprintf(stderr, "RECORD_LOCK_FAIL line=%d errno=%d expression=%s\n", __LINE__, errno,  \
                    #expression);                                                                  \
            exit(1);                                                                               \
        }                                                                                          \
    } while (0)

static unsigned observations;
static volatile sig_atomic_t interrupted;

static void observed(const char* name) {
    printf("RECORD_LOCK_OBSERVATION %s\n", name);
    fflush(stdout);
    observations++;
}

static void handler(int signal) {
    (void)signal;
    interrupted = 1;
}

static struct flock region(short type, off_t first, off_t length) {
    return (struct flock){.l_type = type, .l_whence = SEEK_SET, .l_start = first, .l_len = length};
}

static void set(int fd, int command, short type, off_t first, off_t length) {
    struct flock lock = region(type, first, length);
    CHECK(fcntl(fd, command, &lock) == 0);
}

static void reap(pid_t child) {
    int status;
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

static void byte(int fd, int writing) {
    char value = 'x';
    CHECK((writing ? write(fd, &value, 1) : read(fd, &value, 1)) == 1 && value == 'x');
}

static void conflict(int fd, short expected, off_t first, off_t length, pid_t pid) {
    struct flock request = region(F_WRLCK, first, 1);
    CHECK(fcntl(fd, F_GETLK, &request) == 0);
    CHECK(request.l_type == expected);
    if (expected != F_UNLCK)
        CHECK(request.l_whence == SEEK_SET && request.l_start == first && request.l_len == length &&
              request.l_pid == pid);
}

struct member {
    int started, finish;
};

static void* sibling(void* opaque) {
    struct member* member = opaque;
    byte(member->started, 1);
    byte(member->finish, 0);
    return NULL;
}

static void exec_lifetime(const char* path, const char* observer, int external) {
    for (int cloexec = 0; cloexec < 2; cloexec++) {
        int ready[2], finish[2];
        CHECK(pipe(ready) == 0 && pipe(finish) == 0);
        pid_t child = fork();
        CHECK(child >= 0);
        if (!child) {
            close(ready[0]);
            close(finish[1]);
            int file = open(path, O_RDWR), started[2], wait[2];
            CHECK(file >= 0 && pipe(started) == 0 && pipe(wait) == 0);
            set(file, F_SETLK, F_WRLCK, 100, 1);
            set(file, F_OFD_SETLK, F_WRLCK, 110, 1);
            if (cloexec) {
                int duplicate = dup(file);
                CHECK(duplicate >= 0 && fcntl(duplicate, F_SETFD, FD_CLOEXEC) == 0);
            }
            struct member member = {started[1], wait[0]};
            pthread_t thread;
            CHECK(pthread_create(&thread, NULL, sibling, &member) == 0);
            byte(started[0], 0);
            char inherited[3][32];
            snprintf(inherited[0], sizeof(inherited[0]), "%d", file);
            snprintf(inherited[1], sizeof(inherited[1]), "%d", ready[1]);
            snprintf(inherited[2], sizeof(inherited[2]), "%d", finish[0]);
            execl(observer, observer, inherited[0], inherited[1], inherited[2], NULL);
            CHECK(0);
        }
        close(ready[1]);
        close(finish[0]);
        byte(ready[0], 0);
        conflict(external, cloexec ? F_UNLCK : F_WRLCK, 100, 1, child);
        conflict(external, F_WRLCK, 110, 1, -1);
        byte(finish[1], 1);
        reap(child);
        close(ready[0]);
        close(finish[1]);
        conflict(external, F_UNLCK, 100, 1, 0);
        conflict(external, F_UNLCK, 110, 1, 0);
    }
    observed("multithreaded_exec_preserves_posix_ofd_locks_and_cloexec_releases_posix");
}

int main(int argc, char** argv) {
    CHECK(argc == 3);
    int file = open(argv[1], O_RDWR | O_CREAT | O_EXCL, 0644);
    CHECK(file >= 0 && ftruncate(file, 256) == 0);
    int alias = open(argv[1], O_RDWR);
    CHECK(alias >= 0);
    CHECK(lseek(file, 100, SEEK_SET) == 100);
    struct flock lock = {.l_type = F_RDLCK, .l_whence = SEEK_CUR, .l_start = -10, .l_len = 20};
    CHECK(fcntl(file, F_SETLK, &lock) == 0);
    pid_t parent = getpid(), child = fork();
    CHECK(child >= 0);
    if (!child) {
        conflict(alias, F_RDLCK, 90, 20, parent);
        lock = region(F_WRLCK, 100, 1);
        CHECK(fcntl(alias, F_SETLK, &lock) == -1 && (errno == EAGAIN || errno == EACCES));
        set(alias, F_SETLK, F_RDLCK, 90, 20);
        _exit(0);
    }
    reap(child);
    lock = region(F_WRLCK, 90, 1);
    lock.l_whence = SEEK_CUR;
    lock.l_start = -10;
    lock.l_pid = 123;
    CHECK(fcntl(file, F_GETLK, &lock) == 0 && lock.l_type == F_UNLCK);
    CHECK(lock.l_whence == SEEK_CUR && lock.l_start == -10 && lock.l_len == 1 && lock.l_pid == 123);
    observed("normalized_ranges_foreign_pid_shared_reads_own_queries_preserve_fields");
    set(file, F_SETLK, F_WRLCK, 95, 5);
    child = fork();
    CHECK(child >= 0);
    if (!child) {
        conflict(alias, F_RDLCK, 90, 5, parent);
        conflict(alias, F_WRLCK, 95, 5, parent);
        conflict(alias, F_RDLCK, 100, 10, parent);
        _exit(0);
    }
    reap(child);
    set(file, F_SETLK, F_UNLCK, 96, 2);
    child = fork();
    CHECK(child >= 0);
    if (!child) {
        conflict(alias, F_UNLCK, 96, 0, 0);
        _exit(0);
    }
    reap(child);
    set(file, F_SETLK, F_WRLCK, 90, 20);
    child = fork();
    CHECK(child >= 0);
    if (!child) {
        conflict(alias, F_WRLCK, 90, 20, parent);
        _exit(0);
    }
    reap(child);
    observed("conversion_split_partial_unlock_and_coalescing");
    close(alias);
    alias = open(argv[1], O_RDWR);
    CHECK(alias >= 0);
    child = fork();
    CHECK(child >= 0);
    if (!child) {
        conflict(alias, F_UNLCK, 90, 0, 0);
        _exit(0);
    }
    reap(child);
    observed("closing_any_descriptor_releases_all_process_locks_on_inode");
    set(file, F_OFD_SETLK, F_WRLCK, 0, 0);
    child = fork();
    CHECK(child >= 0);
    if (!child) {
        lock = region(F_WRLCK, 0, 1);
        CHECK(fcntl(alias, F_GETLK, &lock) == 0 && lock.l_type == F_WRLCK && lock.l_pid == -1);
        set(file, F_OFD_SETLK, F_RDLCK, 0, 0);
        _exit(0);
    }
    reap(child);
    lock = region(F_WRLCK, 0, 1);
    CHECK(fcntl(alias, F_GETLK, &lock) == 0 && lock.l_type == F_RDLCK && lock.l_pid == -1);
    lock.l_type = F_WRLCK;
    CHECK(fcntl(alias, F_SETLK, &lock) == -1 && errno == EAGAIN);
    int duplicate = dup(file);
    CHECK(duplicate >= 0);
    close(file);
    lock = region(F_WRLCK, 0, 1);
    CHECK(fcntl(alias, F_OFD_GETLK, &lock) == 0 && lock.l_type == F_RDLCK && lock.l_pid == -1);
    close(duplicate);
    lock = region(F_WRLCK, 0, 1);
    CHECK(fcntl(alias, F_GETLK, &lock) == 0 && lock.l_type == F_UNLCK);
    observed("ofd_fork_conversion_cross_owner_conflict_and_final_description_close");
    set(alias, F_SETLK, F_WRLCK, 0, 1);
    int ready[2], finished[2];
    CHECK(pipe(ready) == 0 && pipe(finished) == 0);
    child = fork();
    CHECK(child >= 0);
    if (!child) {
        close(ready[0]);
        close(finished[0]);
        byte(ready[1], 1);
        set(alias, F_SETLKW, F_WRLCK, 0, 1);
        byte(finished[1], 1);
        _exit(0);
    }
    close(ready[1]);
    close(finished[1]);
    byte(ready[0], 0);
    CHECK(fcntl(finished[0], F_SETFL, O_NONBLOCK) == 0);
    char value;
    CHECK(read(finished[0], &value, 1) == -1 && errno == EAGAIN);
    set(alias, F_SETLK, F_UNLCK, 0, 1);
    CHECK(fcntl(finished[0], F_SETFL, 0) == 0);
    byte(finished[0], 0);
    reap(child);
    close(ready[0]);
    close(finished[0]);
    observed("real_blocking_lock_wakes_after_conflicting_owner_unlock");
    set(alias, F_SETLK, F_WRLCK, 0, 1);
    CHECK(pipe(ready) == 0);
    child = fork();
    CHECK(child >= 0);
    if (!child) {
        close(ready[0]);
        struct sigaction action = {.sa_handler = handler};
        CHECK(sigaction(SIGUSR1, &action, NULL) == 0);
        byte(ready[1], 1);
        lock = region(F_WRLCK, 0, 1);
        CHECK(fcntl(alias, F_SETLKW, &lock) == -1 && errno == EINTR && interrupted);
        _exit(0);
    }
    close(ready[1]);
    byte(ready[0], 0);
    usleep(20000);
    CHECK(kill(child, SIGUSR1) == 0);
    reap(child);
    close(ready[0]);
    set(alias, F_SETLK, F_UNLCK, 0, 0);
    observed("caught_signal_interrupts_waiting_process_lock");
    int read_only = open(argv[1], O_RDONLY);
    CHECK(read_only >= 0);
    lock = region(F_WRLCK, 0, 1);
    CHECK(fcntl(read_only, F_SETLK, &lock) == -1 && errno == EBADF);
    lock = region(F_RDLCK, -1, 1);
    CHECK(fcntl(alias, F_SETLK, &lock) == -1 && errno == EINVAL);
    lock = region(F_RDLCK, 10, -5);
    CHECK(fcntl(alias, F_SETLK, &lock) == 0);
    lock = region(F_WRLCK, 0, 1);
    lock.l_pid = 1;
    CHECK(fcntl(alias, F_OFD_SETLK, &lock) == -1 && errno == EINVAL);
    close(read_only);
    exec_lifetime(argv[1], argv[2], alias);
    close(alias);
    observed("access_errors_negative_ranges_and_ofd_pid_validation");
    printf("RECORD_LOCK_PASS observations=%u\n", observations);
    return 0;
}
