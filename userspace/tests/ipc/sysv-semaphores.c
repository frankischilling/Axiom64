// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <errno.h>
#include <grp.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sem.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

union sem_argument {
    int value;
    struct semid_ds* info;
    unsigned short* values;
};

static void check(int condition, const char* operation) {
    if (!condition) {
        fprintf(stderr, "SYSV_SEM_FAIL %s errno=%d\n", operation, errno);
        _exit(1);
    }
}

static void wait_ok(pid_t child) {
    int status;
    check(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0,
          "child completion");
}

static void become_ordinary(void) {
    check(!setgroups(0, NULL) && !setgid(65534) && !setuid(65534), "ordinary credentials");
}

static void set(int id, int number, int value) {
    check(!semctl(id, number, SETVAL, (union sem_argument){.value = value}), "SETVAL");
}

static void adjust(int id, short value, short flags) {
    struct sembuf change = {.sem_num = 0, .sem_op = value, .sem_flg = flags};
    check(!semop(id, &change, 1), "successful semop");
}

static long elapsed_ns(struct timespec begin, struct timespec end) {
    return (end.tv_sec - begin.tv_sec) * 1000000000L + end.tv_nsec - begin.tv_nsec;
}

static void wait_for_value(int id, int operation) {
    for (unsigned attempt = 0; attempt < 200; ++attempt) {
        if (semctl(id, 0, operation) == 1)
            return;
        struct timespec delay = {.tv_nsec = 5000000};
        check(!nanosleep(&delay, NULL), "waiter observation sleep");
    }
    check(0, "actual waiter registered");
}

static void handle(int signo) {
    (void)signo;
}

static int shared_undo(void* value) {
    int id = *(int*)value;
    adjust(id, -1, SEM_UNDO);
    return 0;
}

struct shared_request {
    int id;
    struct sembuf operation;
};

static int run_request(void* argument) {
    struct shared_request* request = argument;
    check(!semop(request->id, &request->operation, 1), "retained blocked operation");
    return 0;
}

static void keys(void) {
    key_t key = 0x5a000000 | getpid();
    check(semget(key, 0, 0600) == -1 && errno == ENOENT, "missing key");
    int id = semget(key, 2, IPC_CREAT | IPC_EXCL | 0600);
    check(id >= 0 && semget(key, 0, 0400) == id, "lookup returns existing key");
    check(semget(key, 0, IPC_CREAT | IPC_EXCL | 0600) == -1 && errno == EEXIST,
          "exclusive create rejects existing key");
    check(semget(key, 3, 0600) == -1 && errno == EINVAL, "lookup size checked");
    check(!semctl(id, 0, IPC_RMID), "remove named set");
    int replacement = semget(key, 2, IPC_CREAT | IPC_EXCL | 0600);
    check(replacement >= 0 && replacement != id, "removed key can be recreated with fresh id");
    check(semctl(id, 0, GETVAL) == -1 && errno == EINVAL, "old id cannot reach replacement");
    check(!semctl(replacement, 0, IPC_RMID), "remove replacement");
}

int main(int argc, char** argv) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    alarm(15);
    if (argc == 3 && !strcmp(argv[1], "--check-undo")) {
        check(semctl(atoi(argv[2]), 0, GETVAL) == 2, "exec preserves pending undo");
        return 0;
    }
    check(argc == 1 || (argc == 2 && !strcmp(argv[1], "--ordinary")), "arguments");
    if (argc == 2)
        become_ordinary();
    keys();
    int id = semget(IPC_PRIVATE, 2, 0600);
    check(id >= 0, "semget creates private set");
    struct semid_ds info;
    check(!semctl(id, 0, IPC_STAT, (union sem_argument){.info = &info}) && info.sem_nsems == 2 &&
              info.sem_otime == 0 && info.sem_ctime > 0,
          "initial semaphore metadata");
    check(info.sem_perm.uid == getuid() && info.sem_perm.gid == getgid() &&
              (info.sem_perm.mode & 0777) == 0600,
          "new set records effective owner and mode");
    info.sem_perm.mode = 0640;
    check(!semctl(id, 0, IPC_SET, (union sem_argument){.info = &info}) &&
              !semctl(id, 0, IPC_STAT, (union sem_argument){.info = &info}) &&
              (info.sem_perm.mode & 0777) == 0640,
          "owner changes and reads back the mode");
    unsigned short values[2] = {2, 0};
    check(!semctl(id, 0, SETALL, (union sem_argument){.values = values}), "initial SETALL");
    unsigned short invalid_values[2] = {3, 32768};
    check(semctl(id, 0, SETALL, (union sem_argument){.values = invalid_values}) == -1 &&
              errno == ERANGE && semctl(id, 0, GETVAL) == 2 && semctl(id, 1, GETVAL) == 0,
          "failed SETALL leaves the complete set unchanged");
    struct sembuf vector[2] = {{0, -1, 0}, {1, -1, IPC_NOWAIT}};
    check(semop(id, vector, 2) == -1 && errno == EAGAIN && semctl(id, 0, GETVAL) == 2 &&
              semctl(id, 1, GETVAL) == 0,
          "whole operation vector rolls back at failed member");
    vector[1].sem_op = 1;
    check(!semop(id, vector, 2) && semctl(id, 0, GETPID) == getpid() &&
              semctl(id, 0, GETVAL) == 1 && semctl(id, 1, GETVAL) == 1,
          "successful vector publishes both values and owner");
    struct sembuf invalid = {.sem_num = 2, .sem_op = 0};
    check(semop(id, &invalid, 1) == -1 && errno == EFBIG, "invalid semaphore number");
    struct sembuf blocked = {.sem_num = 0, .sem_op = -2};
    struct timespec bound = {.tv_nsec = 40000000}, begin, end;
    check(!clock_gettime(CLOCK_MONOTONIC, &begin), "monotonic start");
    check(semtimedop(id, &blocked, 1, &bound) == -1 && errno == EAGAIN, "finite wait errno");
    check(!clock_gettime(CLOCK_MONOTONIC, &end) && elapsed_ns(begin, end) >= 40000000 &&
              bound.tv_nsec == 40000000,
          "relative deadline reached and timeout argument preserved");
    printf("atomic_vector timed_wait_ns=%ld invalid_index=EFBIG\n", elapsed_ns(begin, end));

    pid_t child = fork();
    check(child >= 0, "fork interrupted waiter");
    if (!child) {
        struct sigaction action = {.sa_handler = handle, .sa_flags = SA_RESTART};
        check(!sigemptyset(&action.sa_mask) && !sigaction(SIGUSR1, &action, NULL),
              "signal handler");
        check(semop(id, &blocked, 1) == -1 && errno == EINTR, "semop never restarts on signal");
        _exit(0);
    }
    wait_for_value(id, GETNCNT);
    check(!kill(child, SIGUSR1), "interrupt recorded waiter");
    wait_ok(child);
    check(semctl(id, 0, GETNCNT) == 0, "interrupted waiter reclaimed");

    struct shared_request request = {.id = id, .operation = {.sem_num = 0, .sem_op = -2}};
    void* waiter_stack = malloc(65536);
    check(waiter_stack != NULL, "shared VM waiter stack");
    child = clone(run_request, (unsigned char*)waiter_stack + 65536, CLONE_VM | SIGCHLD, &request);
    check(child >= 0, "fork shared VM waiter");
    wait_for_value(id, GETNCNT);
    request.operation.sem_op = 1;
    set(id, 0, 2);
    wait_ok(child);
    check(semctl(id, 0, GETVAL) == 0, "queued operation retains its original user input");
    free(waiter_stack);

    set(id, 0, 3);
    child = fork();
    check(child >= 0, "fork undo owner");
    if (!child) {
        adjust(id, -1, SEM_UNDO);
        pid_t plain = fork();
        check(plain >= 0, "fork without undo inheritance");
        if (!plain)
            _exit(0);
        wait_ok(plain);
        check(semctl(id, 0, GETVAL) == 2, "ordinary fork does not inherit pending undo");
        void* stack = malloc(65536);
        check(stack != NULL, "clone stack");
        pid_t shared =
            clone(shared_undo, (unsigned char*)stack + 65536, CLONE_SYSVSEM | SIGCHLD, &id);
        check(shared >= 0, "clone with shared semaphore undo");
        wait_ok(shared);
        check(semctl(id, 0, GETVAL) == 1, "nonfinal shared undo owner cannot apply adjustments");
        free(stack);
        _exit(0);
    }
    wait_ok(child);
    check(semctl(id, 0, GETVAL) == 3, "last shared owner applies both adjustments");
    child = fork();
    check(child >= 0, "fork exec undo owner");
    if (!child) {
        adjust(id, -1, SEM_UNDO);
        char number[16];
        int size = snprintf(number, sizeof(number), "%d", id);
        check(size > 0 && (size_t)size < sizeof(number), "format exec semaphore id");
        execl(argv[0], argv[0], "--check-undo", number, (char*)NULL);
        check(0, "exec same client");
    }
    wait_ok(child);
    check(semctl(id, 0, GETVAL) == 3, "exec retains undo until final exit");
    puts("signal=EINTR ordinary_fork=no_undo shared_owner_exit=last");

    int ready[2], release[2];
    check(!pipe(ready) && !pipe(release), "SETVAL barrier pipes");
    child = fork();
    check(child >= 0, "fork undo reset owner");
    if (!child) {
        char value;
        adjust(id, -1, SEM_UNDO);
        check(write(ready[1], "r", 1) == 1 && read(release[0], &value, 1) == 1,
              "undo reset barrier");
        _exit(0);
    }
    char marker;
    check(read(ready[0], &marker, 1) == 1 && semctl(id, 0, GETVAL) == 2, "pending undo adjustment");
    set(id, 0, 7);
    check(write(release[1], "x", 1) == 1, "release undo owner");
    wait_ok(child);
    check(semctl(id, 0, GETVAL) == 7, "SETVAL clears other owners' adjustments");
    for (int end_index = 0; end_index < 2; ++end_index) {
        close(ready[end_index]);
        close(release[end_index]);
    }

    if (!getuid()) {
        child = fork();
        check(child >= 0, "fork permission check");
        if (!child) {
            become_ordinary();
            check(semctl(id, 0, GETVAL) == -1 && errno == EACCES, "ordinary read denied");
            check(semctl(id, 0, IPC_RMID) == -1 && errno == EPERM, "ordinary removal denied");
            _exit(0);
        }
        wait_ok(child);
        puts("inaccessible=EACCES nonowner_removal=EPERM");
    }
    child = fork();
    check(child >= 0, "fork zero waiter");
    if (!child) {
        struct sembuf zero = {.sem_num = 0, .sem_op = 0};
        check(semop(id, &zero, 1) == -1 && errno == EIDRM, "removed set wakes zero waiter");
        _exit(0);
    }
    wait_for_value(id, GETZCNT);
    check(!semctl(id, 0, IPC_RMID), "remove set with live waiter");
    wait_ok(child);
    check(semctl(id, 0, GETVAL) == -1 && errno == EINVAL, "stale identifier rejected");
    puts("SETVAL=clears_undo waiter_removal=EIDRM stale=EINVAL");
    printf("SYSV_SEM_PASS uid=%u\n", (unsigned)getuid());
    return 0;
}
