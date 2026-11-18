// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <linux/futex.h>
#include <semaphore.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static void check(int success, const char* operation) {
    if (!success) {
        fprintf(stderr, "POSIX_SEM_FAIL %s errno=%d\n", operation, errno);
        _exit(1);
    }
}

#define fails(call, error) check((call) == -1 && errno == (error), #call)
#define open_fails(call, error) check((call) == SEM_FAILED && errno == (error), #call)

static void ordinary(void) {
    check(!setgroups(0, NULL) && !setgid(65534) && !setuid(65534), "ordinary credentials");
}

static unsigned wait_code(pid_t child) {
    int status;
    check(waitpid(child, &status, 0) == child && WIFEXITED(status), "child exited");
    return WEXITSTATUS(status);
}

static void wait_sleeping(pid_t child) {
    char path[64], status[1024];
    check(snprintf(path, sizeof(path), "/proc/%d/status", (int)child) > 0, "proc path");
    for (unsigned attempt = 0; attempt < 200; ++attempt) {
        int fd = open(path, O_RDONLY);
        check(fd >= 0, "open child status");
        ssize_t bytes = read(fd, status, sizeof(status) - 1);
        check(bytes > 0 && !close(fd), "read child status");
        status[bytes] = 0;
        if (strstr(status, "\nState:\tS"))
            return;
        check(!strstr(status, "\nState:\tZ"), "waiter still live");
        check(!nanosleep(&(struct timespec){.tv_nsec = 5000000}, NULL), "waiter observation");
    }
    check(0, "child reached semaphore wait");
}

static void name_for(char name[64], const char* case_name) {
    int length = snprintf(name, 64, "/axiom-sem-%u-%s", (unsigned)getpid(), case_name);
    check(length > 0 && length < 64, "semaphore name fits");
}

static void expect_value(sem_t* semaphore, int expected) {
    int value;
    check(!sem_getvalue(semaphore, &value) && value == expected, "semaphore value");
}

static void wait_realtime_deadline(sem_t* semaphore) {
    struct timespec deadline, returned;
    check(!clock_gettime(CLOCK_REALTIME, &deadline), "read realtime before wait");
    deadline.tv_nsec += 150000000;
    if (deadline.tv_nsec >= 1000000000) {
        deadline.tv_nsec -= 1000000000;
        ++deadline.tv_sec;
    }
    fails(sem_timedwait(semaphore, &deadline), ETIMEDOUT);
    check(!clock_gettime(CLOCK_REALTIME, &returned) &&
              (returned.tv_sec > deadline.tv_sec ||
               (returned.tv_sec == deadline.tv_sec && returned.tv_nsec >= deadline.tv_nsec)),
          "actual realtime deadline elapsed");
}

static void handle(int signal) {
    (void)signal;
}

static volatile sig_atomic_t signal_writer;

static void acknowledge(int signal) {
    (void)signal;
    if (write(signal_writer, "s", 1) != 1)
        _exit(3);
}

static void restart_contract(unsigned* word, int timed) {
    int acknowledgment[2];
    check(!pipe(acknowledgment), "restart signal barrier");
    pid_t child = fork();
    check(child >= 0, "fork restart waiter");
    if (!child) {
        check(!close(acknowledgment[0]), "close restart barrier reader");
        signal_writer = acknowledgment[1];
        struct sigaction action = {.sa_handler = acknowledge, .sa_flags = SA_RESTART};
        check(!sigemptyset(&action.sa_mask) && !sigaction(SIGUSR1, &action, NULL),
              "install restarting signal handler");
        if (timed) {
            const struct timespec timeout = {.tv_sec = 2};
            fails(syscall(SYS_futex, word, FUTEX_WAIT, 0, &timeout, NULL, 0), EINTR);
        } else {
            check(!syscall(SYS_futex, word, FUTEX_WAIT, 0, NULL, NULL, 0),
                  "SA_RESTART retries the untimed futex wait");
        }
        _exit(0);
    }
    check(!close(acknowledgment[1]), "close restart barrier writer");
    wait_sleeping(child);
    char token;
    check(!kill(child, SIGUSR1) && read(acknowledgment[0], &token, 1) == 1 &&
              !close(acknowledgment[0]),
          "actual waiter ran its restart handler");
    if (!timed) {
        int woken = 0;
        for (unsigned attempt = 0; attempt < 200 && !woken; ++attempt) {
            woken = syscall(SYS_futex, word, FUTEX_WAKE, 1, NULL, NULL, 0);
            check(woken >= 0, "wake restarted futex");
            if (!woken)
                check(!nanosleep(&(struct timespec){.tv_nsec = 5000000}, NULL),
                      "wait for futex requeue");
        }
        check(woken == 1, "restart requeued the original wait");
    }
    check(!wait_code(child), "waiter obeyed timed or untimed restart rule");
}

static void unnamed(void) {
    sem_t local;
    check(!sem_init(&local, 0, 1) && !sem_trywait(&local), "process-private semaphore");
    fails(sem_trywait(&local), EAGAIN);
    wait_realtime_deadline(&local);
    check(!sem_destroy(&local), "destroy process-private semaphore");
    fails(sem_init(&local, 0, (unsigned)SEM_VALUE_MAX + 1), EINVAL);
    check(!sem_init(&local, 0, SEM_VALUE_MAX), "initialize with maximum permit count");
    fails(sem_post(&local), EOVERFLOW);
    expect_value(&local, SEM_VALUE_MAX);
    check(!sem_destroy(&local), "destroy saturated semaphore");

    sem_t* shared = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    check(shared != MAP_FAILED && !sem_init(shared, 1, 0), "process-shared anonymous semaphore");
    pid_t child = fork();
    check(child >= 0, "fork shared waiter");
    if (!child)
        _exit(sem_wait(shared) ? 2 : 0);
    wait_sleeping(child);
    check(!sem_post(shared) && !wait_code(child), "post wakes waiting child");
    expect_value(shared, 0);

    child = fork();
    check(child >= 0, "fork interrupted waiter");
    if (!child) {
        struct sigaction action = {.sa_handler = handle};
        check(!sigemptyset(&action.sa_mask) && !sigaction(SIGUSR1, &action, NULL),
              "install signal handler");
        fails(sem_wait(shared), EINTR);
        _exit(0);
    }
    wait_sleeping(child);
    check(!kill(child, SIGUSR1) && !wait_code(child), "interrupt waiting child");
    check(!sem_post(shared) && !sem_trywait(shared), "interrupted wait consumes no post");
    // Use a separate futex word so libc cannot mask the raw signal result.
    unsigned* word = (void*)(shared + 1);
    restart_contract(word, 0);
    restart_contract(word, 1);
    check(!sem_destroy(shared) && !munmap(shared, 4096), "release process-shared semaphore");
}

static void exec_waiter(const char* name, const char* writer) {
    sem_t* semaphore = sem_open(name, 0);
    check(semaphore != SEM_FAILED, "lookup after exec");
    int fd = atoi(writer);
    check(write(fd, "r", 1) == 1 && !close(fd), "exec lookup acknowledged");
    check(!sem_wait(semaphore) && !sem_close(semaphore), "wait after unlink on old named mapping");
}

static void named_lifetime(const char* program) {
    char name[64];
    name_for(name, "lifetime");
    open_fails(sem_open(name, 0), ENOENT);
    sem_t* semaphore = sem_open(name, O_CREAT | O_EXCL, 0600, 0);
    check(semaphore != SEM_FAILED, "create named semaphore");
    open_fails(sem_open(name, O_CREAT | O_EXCL, 0600, 0), EEXIST);
    sem_t* alias = sem_open(name, 0);
    check(alias == semaphore && !sem_close(alias), "named opens share one process mapping");
    wait_realtime_deadline(semaphore);

    int channel[2];
    check(!pipe(channel), "named waiter barrier");
    pid_t child = fork();
    check(child >= 0, "fork named waiter");
    if (!child) {
        check(!close(channel[0]), "close barrier reader in child");
        char writer[16];
        int length = snprintf(writer, sizeof(writer), "%d", channel[1]);
        check(length > 0 && (size_t)length < sizeof(writer), "format barrier descriptor");
        execl(program, program, "--named-waiter", name, writer, (char*)NULL);
        check(0, "exec named waiter");
    }
    char token;
    check(!close(channel[1]) && read(channel[0], &token, 1) == 1 && !close(channel[0]),
          "exec child opened the old name");
    wait_sleeping(child);
    check(!sem_unlink(name), "unlink with parent and child mappings alive");
    open_fails(sem_open(name, 0), ENOENT);
    sem_t* replacement = sem_open(name, O_CREAT | O_EXCL, 0600, 2);
    check(replacement != SEM_FAILED && replacement != semaphore, "replace unlinked semaphore");
    check(!sem_post(semaphore) && !wait_code(child), "old mapping wakes its actual waiter");
    expect_value(semaphore, 0);
    expect_value(replacement, 2);
    check(!sem_close(semaphore) && !sem_close(replacement) && !sem_unlink(name),
          "close old and replacement mappings");
}

static void concurrent_create(void) {
    char name[64];
    name_for(name, "concurrent");
    int gate[2];
    check(!pipe(gate), "concurrent create barrier");
    pid_t children[2];
    for (unsigned i = 0; i < 2; ++i) {
        children[i] = fork();
        check(children[i] >= 0, "fork concurrent creator");
        if (!children[i]) {
            char token;
            check(!close(gate[1]) && read(gate[0], &token, 1) == 1, "release creator");
            sem_t* semaphore = sem_open(name, O_CREAT | O_EXCL, 0600, 1);
            if (semaphore == SEM_FAILED) {
                check(errno == EEXIST, "concurrent create loser");
                _exit(3);
            }
            check(!sem_close(semaphore), "concurrent create winner");
            _exit(2);
        }
    }
    check(!close(gate[0]) && write(gate[1], "gg", 2) == 2 && !close(gate[1]),
          "release both creators");
    unsigned first = wait_code(children[0]), second = wait_code(children[1]);
    check((first == 2 && second == 3) || (first == 3 && second == 2), "one exclusive creator");
    sem_t* semaphore = sem_open(name, 0);
    check(semaphore != SEM_FAILED && !sem_trywait(semaphore), "winner supplied the initial count");
    fails(sem_trywait(semaphore), EAGAIN);
    check(!sem_close(semaphore) && !sem_unlink(name), "remove concurrent test name");
}

static void unlink_denied(const char* name) {
    check(sem_unlink(name) == -1 && (errno == EPERM || errno == EACCES),
          "sticky directory protects the owner's name");
}

static void permissions(void) {
    struct stat directory;
    check(!stat("/dev/shm", &directory) && S_ISDIR(directory.st_mode) && directory.st_uid == 0 &&
              (directory.st_mode & 07777) == 01777,
          "root-owned sticky shared-memory directory");
    if (getuid())
        return;
    char name[64];
    name_for(name, "permissions");
    sem_t* semaphore = sem_open(name, O_CREAT | O_EXCL, 0600, 0);
    check(semaphore != SEM_FAILED, "private owner creates name");
    pid_t child = fork();
    check(child >= 0, "fork denied caller");
    if (!child) {
        check(!sem_close(semaphore), "close inherited mapping before access checks");
        ordinary();
        open_fails(sem_open(name, 0), EACCES);
        unlink_denied(name);
        _exit(0);
    }
    check(!wait_code(child) && !sem_close(semaphore) && !sem_unlink(name),
          "owner removes private semaphore");
    mode_t previous = umask(0);
    semaphore = sem_open(name, O_CREAT | O_EXCL, 0666, 0);
    umask(previous);
    check(semaphore != SEM_FAILED, "owner creates world-writable semaphore");
    child = fork();
    check(child >= 0, "fork permitted caller");
    if (!child) {
        check(!sem_close(semaphore), "close inherited mapping before access checks");
        ordinary();
        sem_t* opened = sem_open(name, 0);
        check(opened != SEM_FAILED && !sem_post(opened) && !sem_close(opened),
              "nonowner uses world-writable semaphore");
        unlink_denied(name);
        _exit(0);
    }
    check(!wait_code(child) && !sem_trywait(semaphore), "nonowner post reached owner");
    check(!sem_close(semaphore) && !sem_unlink(name), "owner removes name");
}

int main(int argc, char** argv) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    alarm(20);
    if (argc == 4 && !strcmp(argv[1], "--named-waiter")) {
        exec_waiter(argv[2], argv[3]);
        return 0;
    }
    check(argc == 1 || (argc == 2 && !strcmp(argv[1], "--ordinary")), "arguments");
    if (argc == 2)
        ordinary();
    unnamed();
    puts("POSIX_SEM_CASE unnamed");
    named_lifetime(argv[0]);
    puts("POSIX_SEM_CASE named-lifetime");
    concurrent_create();
    puts("POSIX_SEM_CASE concurrent-create");
    permissions();
    puts("POSIX_SEM_CASE permissions");
    printf("POSIX_SEM_PASS uid=%u\n", (unsigned)getuid());
    return 0;
}
