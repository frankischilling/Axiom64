// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/select.h>
#include <sys/signalfd.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define CHECK(condition)                                                                           \
    do {                                                                                           \
        if (!(condition)) {                                                                        \
            fprintf(stderr, "SIGNALFD_FAIL line=%d %s errno=%d\n", __LINE__, #condition, errno);   \
            exit(1);                                                                               \
        }                                                                                          \
    } while (0)
#define ERROR(call, expected) CHECK((call) == -1 && errno == (expected))

static sigset_t signals(int first, int second) {
    sigset_t set;
    CHECK(sigemptyset(&set) == 0 && sigaddset(&set, first) == 0);
    if (second)
        CHECK(sigaddset(&set, second) == 0);
    return set;
}

static void check_record(const struct signalfd_siginfo* record, int signal, int code, pid_t sender,
                         int status) {
    struct signalfd_siginfo expected = {.ssi_signo = (uint32_t)signal,
                                        .ssi_code = code,
                                        .ssi_pid = (uint32_t)sender,
                                        .ssi_uid = getuid(),
                                        .ssi_status = status};
    CHECK(memcmp(record, &expected, sizeof(expected)) == 0);
}

static void child_status(pid_t child, int expected) {
    int status;
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) &&
          WEXITSTATUS(status) == expected);
}

static void creation(const sigset_t* mask, int legacy) {
    uint64_t raw_mask = (1ull << (SIGUSR1 - 1));
    long old = syscall(SYS_signalfd, -1, &raw_mask, sizeof(raw_mask));
    CHECK(old >= 0 && fcntl((int)old, F_GETFL) == O_RDWR && fcntl((int)old, F_GETFD) == 0);
    CHECK(close((int)old) == 0);
    ERROR(syscall(SYS_signalfd4, -1, NULL, 7, -1), EINVAL);
    ERROR(syscall(SYS_signalfd4, -1, NULL, 8, -1), EFAULT);
    ERROR(syscall(SYS_signalfd4, -3, &raw_mask, 8, -1), EINVAL);
    ERROR(syscall(SYS_signalfd4, -3, &raw_mask, 8, 0), EBADF);

    int descriptor = signalfd(-1, mask, SFD_NONBLOCK | SFD_CLOEXEC);
    int alias = dup(descriptor);
    CHECK(descriptor >= 0 && alias >= 0);
    CHECK(fcntl(descriptor, F_GETFL) == (O_RDWR | O_NONBLOCK) &&
          fcntl(descriptor, F_GETFD) == FD_CLOEXEC && fcntl(alias, F_GETFD) == 0);
    struct stat info;
    CHECK(fstat(descriptor, &info) == 0 && info.st_mode == 0600 && info.st_nlink == 1);
    struct signalfd_siginfo record;
    if (legacy)
        ERROR(lseek(descriptor, 7, SEEK_SET), ESPIPE);
    else
        CHECK(lseek(descriptor, 7, SEEK_SET) == 0);
    ERROR(pread(descriptor, &record, sizeof(record), 0), ESPIPE);
    ERROR(write(descriptor, &record, sizeof(record)), EINVAL);

    int pipe_fds[2];
    CHECK(pipe(pipe_fds) == 0);
    ERROR(signalfd(pipe_fds[0], mask, 0), EINVAL);
    CHECK(close(pipe_fds[0]) == 0 && close(pipe_fds[1]) == 0);
    sigset_t only_second = signals(SIGUSR2, 0);
    CHECK(signalfd(alias, &only_second, SFD_CLOEXEC) == alias);
    CHECK(fcntl(alias, F_GETFD) == 0 && fcntl(descriptor, F_GETFL) == (O_RDWR | O_NONBLOCK));
    CHECK(kill(getpid(), SIGUSR1) == 0 && kill(getpid(), SIGUSR2) == 0);
    CHECK(read(descriptor, &record, sizeof(record)) == sizeof(record));
    check_record(&record, SIGUSR2, SI_USER, getpid(), 0);
    ERROR(read(alias, &record, sizeof(record)), EAGAIN);
    CHECK(signalfd(alias, mask, 0) == alias && close(descriptor) == 0);
    CHECK(read(alias, &record, sizeof(record)) == sizeof(record));
    check_record(&record, SIGUSR1, SI_USER, getpid(), 0);
    CHECK(close(alias) == 0);
    puts("SIGNALFD_CASE creation");
}

static void read_contract(const sigset_t* mask, int legacy) {
    int descriptor = signalfd(-1, mask, SFD_NONBLOCK);
    CHECK(descriptor >= 0);
    struct signalfd_siginfo records[3];
    ERROR(read(descriptor, records, 0), EINVAL);
    ERROR(read(descriptor, records, sizeof(records[0]) - 1), EINVAL);
    CHECK(readv(descriptor, NULL, 0) == 0);
    ERROR(read(descriptor, records, sizeof(records)), EAGAIN);

    CHECK(kill(getpid(), SIGUSR1) == 0 && kill(getpid(), SIGUSR1) == 0);
    CHECK(syscall(SYS_tgkill, getpid(), syscall(SYS_gettid), SIGUSR2) == 0);
    CHECK(read(descriptor, records, sizeof(records) - 1) == 2 * sizeof(records[0]));
    check_record(&records[0], SIGUSR2, SI_TKILL, getpid(), 0);
    check_record(&records[1], SIGUSR1, SI_USER, getpid(), 0);
    ERROR(read(descriptor, records, sizeof(records)), EAGAIN);

    CHECK(kill(getpid(), SIGUSR1) == 0);
    struct iovec split[] = {{records, 31}, {(char*)records + 31, 97}};
    if (legacy) {
        ERROR(readv(descriptor, split, 2), EINVAL);
        CHECK(read(descriptor, records, sizeof(records)) == sizeof(records[0]));
    } else
        CHECK(readv(descriptor, split, 2) == sizeof(records[0]));
    check_record(&records[0], SIGUSR1, SI_USER, getpid(), 0);

    long page = sysconf(_SC_PAGESIZE);
    CHECK(page >= 4096);
    char* memory = mmap(NULL, 2 * page, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(memory != MAP_FAILED && mprotect(memory + page, page, PROT_NONE) == 0);
    CHECK(kill(getpid(), SIGUSR1) == 0);
    ERROR(read(descriptor, memory + page - 64, 128), EFAULT);
    ERROR(read(descriptor, records, sizeof(records)), EAGAIN);
    CHECK(kill(getpid(), SIGUSR1) == 0 && kill(getpid(), SIGUSR2) == 0);
    CHECK(read(descriptor, memory + page - 128, 256) == 128);
    check_record((const struct signalfd_siginfo*)(memory + page - 128), SIGUSR1, SI_USER, getpid(),
                 0);
    ERROR(read(descriptor, records, sizeof(records)), EAGAIN);
    CHECK(munmap(memory, 2 * page) == 0 && close(descriptor) == 0);
    puts("SIGNALFD_CASE read");
}

static void readiness(const sigset_t* mask) {
    int descriptor = signalfd(-1, mask, SFD_NONBLOCK);
    int alias = dup(descriptor);
    int epoll = epoll_create1(EPOLL_CLOEXEC);
    CHECK(descriptor >= 0 && alias >= 0 && epoll >= 0);
    struct epoll_event event = {.events = EPOLLIN | EPOLLET, .data.u64 = 81};
    CHECK(epoll_ctl(epoll, EPOLL_CTL_ADD, descriptor, &event) == 0);
    CHECK(close(descriptor) == 0);
    CHECK(kill(getpid(), SIGUSR1) == 0);
    struct pollfd poller = {alias, POLLIN | POLLOUT, 0};
    CHECK(poll(&poller, 1, 0) == 1 && poller.revents == POLLIN);
    fd_set readable, writable;
    FD_ZERO(&readable);
    FD_ZERO(&writable);
    FD_SET(alias, &readable);
    FD_SET(alias, &writable);
    struct timeval timeout = {0, 0};
    CHECK(select(alias + 1, &readable, &writable, NULL, &timeout) == 1 &&
          FD_ISSET(alias, &readable) && !FD_ISSET(alias, &writable));
    CHECK(epoll_wait(epoll, &event, 1, 0) == 1 && event.events == EPOLLIN && event.data.u64 == 81);
    CHECK(epoll_wait(epoll, &event, 1, 0) == 0);
    CHECK(kill(getpid(), SIGUSR2) == 0);
    CHECK(epoll_wait(epoll, &event, 1, 0) == 1 && event.events == EPOLLIN);
    struct signalfd_siginfo records[2];
    CHECK(read(alias, records, sizeof(records)) == sizeof(records));
    check_record(&records[0], SIGUSR1, SI_USER, getpid(), 0);
    check_record(&records[1], SIGUSR2, SI_USER, getpid(), 0);
    fflush(stdout);
    pid_t child = fork();
    CHECK(child >= 0);
    if (!child) {
        CHECK(kill(getpid(), SIGUSR2) == 0);
        CHECK(poll(&poller, 1, 0) == 1 && poller.revents == POLLIN);
        CHECK(epoll_wait(epoll, &event, 1, 0) == 0);
        CHECK(read(alias, records, sizeof(records)) == sizeof(records[0]));
        check_record(&records[0], SIGUSR2, SI_USER, getpid(), 0);
        _exit(0);
    }
    child_status(child, 0);
    ERROR(read(alias, records, sizeof(records)), EAGAIN);
    CHECK(close(alias) == 0);
    CHECK(epoll_wait(epoll, &event, 1, 0) == 0 && close(epoll) == 0);
    puts("SIGNALFD_CASE readiness");
}

static void lifetime(const sigset_t* mask, const char* program) {
    int descriptor = signalfd(-1, mask, 0);
    CHECK(descriptor >= 0);
    pid_t child = fork();
    CHECK(child >= 0);
    if (!child) {
        struct timespec delay = {0, 50000000};
        CHECK(nanosleep(&delay, NULL) == 0 && kill(getppid(), SIGUSR1) == 0);
        _exit(0);
    }
    struct signalfd_siginfo record;
    CHECK(read(descriptor, &record, sizeof(record)) == sizeof(record));
    check_record(&record, SIGUSR1, SI_USER, child, 0);
    child_status(child, 0);
    int closed = signalfd(-1, mask, SFD_NONBLOCK | SFD_CLOEXEC);
    CHECK(closed >= 0);
    child = fork();
    CHECK(child >= 0);
    if (!child) {
        char keep[16], gone[16];
        snprintf(keep, sizeof(keep), "%d", descriptor);
        snprintf(gone, sizeof(gone), "%d", closed);
        CHECK(kill(getpid(), SIGUSR2) == 0);
        execl(program, program, "--exec-child", keep, gone, (char*)NULL);
        CHECK(0 && "exec");
    }
    child_status(child, 0);
    CHECK(close(closed) == 0 && close(descriptor) == 0);
    sigset_t children = signals(SIGCHLD, 0);
    CHECK(sigprocmask(SIG_BLOCK, &children, NULL) == 0);
    int notifications = signalfd(-1, &children, 0);
    CHECK(notifications >= 0);
    child = fork();
    CHECK(child >= 0);
    if (!child) {
        struct timespec start, now;
        CHECK(clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &start) == 0);
        do {
            for (volatile unsigned work = 0; work < 50000; work++)
                ;
            CHECK(clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &now) == 0);
        } while ((now.tv_sec - start.tv_sec) * 1000000000ll + now.tv_nsec - start.tv_nsec <
                 80000000);
        _exit(37);
    }
    CHECK(read(notifications, &record, sizeof(record)) == sizeof(record));
    CHECK(record.ssi_utime + record.ssi_stime >= 5);
    record.ssi_utime = record.ssi_stime = 0;
    check_record(&record, SIGCHLD, CLD_EXITED, child, 37);
    child_status(child, 37);
    CHECK(close(notifications) == 0);
    puts("SIGNALFD_CASE lifetime");
}

static volatile sig_atomic_t caught;

static void remember_signal(int signal) {
    caught = signal;
}

static void interruption(const sigset_t* mask) {
    int descriptor = signalfd(-1, mask, 0);
    CHECK(descriptor >= 0);
    for (int restarting = 0; restarting <= 1; restarting++) {
        caught = 0;
        struct sigaction action = {.sa_handler = remember_signal,
                                   .sa_flags = restarting ? SA_RESTART : 0};
        CHECK(sigemptyset(&action.sa_mask) == 0 && sigaction(SIGURG, &action, NULL) == 0);
        int gate[2];
        CHECK(pipe(gate) == 0);
        pid_t child = fork();
        CHECK(child >= 0);
        if (!child) {
            CHECK(close(gate[1]) == 0);
            char ready;
            struct timespec delay = {0, 50000000};
            CHECK(read(gate[0], &ready, 1) == 1 && nanosleep(&delay, NULL) == 0);
            CHECK(kill(getppid(), SIGURG) == 0 && nanosleep(&delay, NULL) == 0);
            CHECK(kill(getppid(), SIGUSR1) == 0);
            _exit(0);
        }
        CHECK(close(gate[0]) == 0 && write(gate[1], "R", 1) == 1 && close(gate[1]) == 0);
        struct signalfd_siginfo record;
        if (!restarting) {
            ERROR(read(descriptor, &record, sizeof(record)), EINTR);
            CHECK(caught == SIGURG);
        }
        CHECK(read(descriptor, &record, sizeof(record)) == sizeof(record));
        CHECK(caught == SIGURG);
        check_record(&record, SIGUSR1, SI_USER, child, 0);
        child_status(child, 0);
    }
    CHECK(close(descriptor) == 0);
    puts("SIGNALFD_CASE interruption");
}

static volatile sig_atomic_t handler_payload;

static void queued_handler(int signal, siginfo_t* info, void* unused) {
    (void)unused;
    if (signal == info->si_signo && info->si_code == SI_QUEUE && info->si_pid == getpid())
        handler_payload = info->si_value.sival_int;
}

static void queued_signals(void) {
    int low = SIGRTMIN, high = low + 1;
    sigset_t mask = signals(low, high);
    CHECK(sigaddset(&mask, SIGUSR1) == 0 && sigprocmask(SIG_BLOCK, &mask, NULL) == 0);
    int descriptor = signalfd(-1, &mask, SFD_NONBLOCK);
    CHECK(descriptor >= 0);
    uintptr_t first = UINT64_C(0x12345678abc);
    CHECK(sigqueue(getpid(), high, (union sigval){.sival_int = 44}) == 0);
    CHECK(sigqueue(getpid(), low, (union sigval){.sival_ptr = (void*)first}) == 0);
    CHECK(sigqueue(getpid(), low, (union sigval){.sival_int = 22}) == 0);
    CHECK(sigqueue(getpid(), SIGUSR1, (union sigval){.sival_int = 55}) == 0);
    CHECK(sigqueue(getpid(), SIGUSR1, (union sigval){.sival_int = 66}) == 0);
    siginfo_t thread = {0};
    thread.si_signo = high;
    thread.si_code = SI_QUEUE;
    thread.si_pid = getpid();
    thread.si_uid = getuid();
    thread.si_value.sival_int = 77;
    CHECK(syscall(SYS_rt_tgsigqueueinfo, getpid(), syscall(SYS_gettid), high, &thread) == 0);
    siginfo_t received;
    struct timespec immediate = {0, 0};
    CHECK(sigtimedwait(&mask, &received, &immediate) == high && received.si_code == SI_QUEUE &&
          received.si_pid == getpid() && received.si_uid == getuid() &&
          received.si_value.sival_int == 77);
    struct signalfd_siginfo records[4];
    CHECK(read(descriptor, records, sizeof(records)) == sizeof(records));
    CHECK(records[0].ssi_signo == SIGUSR1 && records[0].ssi_int == 55);
    CHECK(records[1].ssi_signo == (uint32_t)low && records[1].ssi_ptr == first &&
          records[1].ssi_int == (int32_t)first);
    CHECK(records[2].ssi_signo == (uint32_t)low && records[2].ssi_int == 22);
    CHECK(records[3].ssi_signo == (uint32_t)high && records[3].ssi_int == 44);
    for (unsigned i = 0; i < 4; i++)
        CHECK(records[i].ssi_code == SI_QUEUE && records[i].ssi_pid == (uint32_t)getpid() &&
              records[i].ssi_uid == getuid());
    ERROR(read(descriptor, records, sizeof(records)), EAGAIN);

    struct rlimit limit, zero;
    CHECK(getrlimit(RLIMIT_SIGPENDING, &limit) == 0);
    zero = limit;
    zero.rlim_cur = 0;
    CHECK(setrlimit(RLIMIT_SIGPENDING, &zero) == 0);
    ERROR(sigqueue(getpid(), low, (union sigval){.sival_int = 99}), EAGAIN);
    ERROR(read(descriptor, records, sizeof(records)), EAGAIN);
    CHECK(setrlimit(RLIMIT_SIGPENDING, &limit) == 0);

    CHECK(sigqueue(getpid(), high, (union sigval){.sival_int = 11}) == 0);
    struct sigaction ignore = {.sa_handler = SIG_IGN};
    struct sigaction previous;
    CHECK(sigemptyset(&ignore.sa_mask) == 0 && sigaction(high, &ignore, &previous) == 0);
    ERROR(read(descriptor, records, sizeof(records)), EAGAIN);
    CHECK(sigaction(high, &previous, NULL) == 0);

    struct sigaction action = {.sa_sigaction = queued_handler, .sa_flags = SA_SIGINFO};
    CHECK(sigemptyset(&action.sa_mask) == 0 && sigaction(low, &action, NULL) == 0);
    CHECK(sigqueue(getpid(), low, (union sigval){.sival_int = 123}) == 0);
    sigset_t only_low = signals(low, 0);
    CHECK(sigprocmask(SIG_UNBLOCK, &only_low, NULL) == 0 && handler_payload == 123);
    CHECK(close(descriptor) == 0);
    puts("SIGNALFD_CASE queued");
}

int main(int argc, char** argv) {
    if (argc == 4 && !strcmp(argv[1], "--exec-child")) {
        ERROR(fcntl(atoi(argv[3]), F_GETFD), EBADF);
        struct signalfd_siginfo record;
        CHECK(read(atoi(argv[2]), &record, sizeof(record)) == sizeof(record));
        check_record(&record, SIGUSR2, SI_USER, getpid(), 0);
        return 0;
    }
    int legacy_readv = 0, legacy_seek = 0;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--legacy-kernel"))
            legacy_readv = legacy_seek = 1;
        else if (!strcmp(argv[i], "--legacy-readv"))
            legacy_readv = 1;
        else if (!strcmp(argv[i], "--legacy-seek"))
            legacy_seek = 1;
        else {
            CHECK(!strcmp(argv[i], "--ordinary"));
            CHECK(setgroups(0, NULL) == 0 && setgid(65534) == 0 && setuid(65534) == 0);
            CHECK(getuid() == 65534 && geteuid() == 65534);
        }
    }
    sigset_t mask = signals(SIGUSR1, SIGUSR2);
    CHECK(sigprocmask(SIG_BLOCK, &mask, NULL) == 0);
    creation(&mask, legacy_seek);
    read_contract(&mask, legacy_readv);
    readiness(&mask);
    interruption(&mask);
    lifetime(&mask, argv[0]);
    queued_signals();
    printf("SIGNALFD_PASS uid=%lu cases=6\n", (unsigned long)getuid());
    return 0;
}
