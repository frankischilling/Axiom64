// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ipc.h>
#include <sys/resource.h>
#include <sys/shm.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define CHECK(expression)                                                                          \
    do {                                                                                           \
        if (!(expression)) {                                                                       \
            fprintf(stderr, "RESOURCE_LIMIT_FAIL line=%d errno=%d expression=%s\n", __LINE__,      \
                    errno, #expression);                                                           \
            _exit(1);                                                                              \
        }                                                                                          \
    } while (0)

static const char* executable;
static unsigned observations;
static volatile sig_atomic_t file_signals;

static void file_signal(int signal) {
    if (signal == SIGXFSZ)
        file_signals++;
}

static struct rlimit nofile(void) {
    struct rlimit result;
    CHECK(getrlimit(RLIMIT_NOFILE, &result) == 0);
    return result;
}

static void soft(rlim_t value) {
    struct rlimit limit = nofile();
    limit.rlim_cur = value;
    CHECK(setrlimit(RLIMIT_NOFILE, &limit) == 0);
}

static void drop_resource_capability(void) {
    struct {
        uint32_t version;
        int32_t pid;
    } header = {0x20080522, 0};

    struct {
        uint32_t effective, permitted, inheritable;
    } values[2];

    CHECK(syscall(SYS_capget, &header, values) == 0);
    values[0].effective &= ~(1u << 24);
    values[0].permitted &= ~(1u << 24);
    values[0].inheritable &= ~(1u << 24);
    CHECK(syscall(SYS_capset, &header, values) == 0);
    CHECK(syscall(SYS_capget, &header, values) == 0 && !(values[0].effective & (1u << 24)));
}

static void interface(void) {
    struct rlimit limit, original = nofile();
    CHECK(sizeof(limit) == 16 && original.rlim_cur >= 32);
    for (unsigned resource = 0; resource < 16; resource++) {
        CHECK(syscall(SYS_getrlimit, resource, &limit) == 0);
        CHECK(limit.rlim_cur <= limit.rlim_max);
    }
    CHECK(syscall(SYS_getrlimit, 16u, &limit) == -1 && errno == EINVAL);
    CHECK(syscall(SYS_getrlimit, UINT_MAX, &limit) == -1 && errno == EINVAL);
    CHECK(syscall(SYS_getrlimit, (UINT64_C(1) << 32) | RLIMIT_NOFILE, &limit) == 0);
    CHECK(limit.rlim_cur == original.rlim_cur && limit.rlim_max == original.rlim_max);
    CHECK(syscall(SYS_getrlimit, 16u, NULL) == -1 && errno == EINVAL);
    CHECK(syscall(SYS_getrlimit, RLIMIT_NOFILE, NULL) == -1 && errno == EFAULT);
    CHECK(syscall(SYS_setrlimit, 16u, NULL) == -1 && errno == EFAULT);
    CHECK(syscall(SYS_prlimit64, 0, RLIMIT_NOFILE, NULL, NULL) == 0);
    CHECK(syscall(SYS_prlimit64, INT_MAX, RLIMIT_NOFILE, NULL, NULL) == -1 && errno == ESRCH);
    CHECK(syscall(SYS_prlimit64, INT_MAX, 16u, (void*)-1, NULL) == -1 && errno == EFAULT);

    long page = sysconf(_SC_PAGESIZE);
    CHECK(page > 0);
    char* memory =
        mmap(NULL, (size_t)page * 2, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(memory != MAP_FAILED && mprotect(memory + page, (size_t)page, PROT_NONE) == 0);
    memcpy(memory + page - 8, &original, 8);
    CHECK(syscall(SYS_setrlimit, RLIMIT_NOFILE, memory + page - 8) == -1 && errno == EFAULT);
    limit = nofile();
    CHECK(limit.rlim_cur == original.rlim_cur && limit.rlim_max == original.rlim_max);
    CHECK(munmap(memory, (size_t)page * 2) == 0);

    limit = original;
    limit.rlim_cur--;
    CHECK(syscall(SYS_setrlimit, RLIMIT_NOFILE, &limit) == 0);
    struct rlimit aliased = limit;
    aliased.rlim_cur--;
    CHECK(syscall(SYS_prlimit64, 0, RLIMIT_NOFILE, &aliased, &aliased) == 0);
    CHECK(aliased.rlim_cur == limit.rlim_cur && aliased.rlim_max == limit.rlim_max);
    limit.rlim_cur -= 2;
    CHECK(syscall(SYS_prlimit64, 0, RLIMIT_NOFILE, &limit, (void*)-1) == -1 && errno == EFAULT);
    CHECK(nofile().rlim_cur == limit.rlim_cur);

    limit = (struct rlimit){8, 16};
    CHECK(setrlimit(RLIMIT_NOFILE, &limit) == 0);
    drop_resource_capability();
    limit = (struct rlimit){16, 32};
    CHECK(setrlimit(RLIMIT_NOFILE, &limit) == -1 && errno == EPERM);
    limit = (struct rlimit){17, 16};
    CHECK(setrlimit(RLIMIT_NOFILE, &limit) == -1 && errno == EINVAL);
    limit = nofile();
    CHECK(limit.rlim_cur == 8 && limit.rlim_max == 16);
}

static void descriptors(void) {
    int low = open("/dev/null", O_RDONLY);
    CHECK(low >= 0);
    int retained = fcntl(low, F_DUPFD_CLOEXEC, 24);
    CHECK(retained >= 24 && close(low) == 0);
    soft(8);
    char byte;
    CHECK(read(retained, &byte, 1) == 0 && dup2(retained, retained) == retained);
    CHECK(dup2(retained, 25) == -1 && errno == EBADF);
    CHECK(fcntl(retained, F_DUPFD, 8) == -1 && errno == EINVAL);
    int held[16], count = 0;
    for (;;) {
        int fd = open("/dev/null", O_RDONLY);
        if (fd < 0) {
            CHECK(errno == EMFILE);
            break;
        }
        CHECK(fd < 8 && count < 16);
        held[count++] = fd;
    }
    CHECK(count >= 2);
    CHECK(close(held[--count]) == 0);
    int pair[2];
    CHECK(pipe(pair) == -1 && errno == EMFILE);
    CHECK(close(held[--count]) == 0 && pipe(pair) == 0);
    CHECK(pair[0] < 8 && pair[1] < 8 && pair[0] != pair[1]);
    CHECK(close(pair[0]) == 0 && close(pair[1]) == 0);
    while (count)
        CHECK(close(held[--count]) == 0);
    soft(0);
    CHECK(open("/dev/null", O_RDONLY) == -1 && errno == EMFILE);
    CHECK(read(retained, &byte, 1) == 0 && dup2(retained, retained) == retained);
    CHECK(close(retained) == 0);
}

static void* change_thread(void* ignored) {
    (void)ignored;
    soft(15);
    struct rlimit limit;
    CHECK(syscall(SYS_prlimit64, syscall(SYS_gettid), RLIMIT_NOFILE, NULL, &limit) == 0);
    CHECK(limit.rlim_cur == 15);
    return NULL;
}

static void lifetime(void) {
    pthread_t thread;
    CHECK(pthread_create(&thread, NULL, change_thread, NULL) == 0);
    CHECK(pthread_join(thread, NULL) == 0 && nofile().rlim_cur == 15);
    pid_t child = fork();
    CHECK(child >= 0);
    if (!child) {
        CHECK(nofile().rlim_cur == 15);
        soft(14);
        char* const arguments[] = {(char*)executable, "--verify-exec", NULL};
        execv(executable, arguments);
        CHECK(0);
    }
    int status;
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    CHECK(nofile().rlim_cur == 15);
}

static void file_size(void) {
    const char* directory = getenv("AXIOM64_RESOURCE_DIRECTORY");
    char path[1024];
    int path_length =
        snprintf(path, sizeof(path), "%s/resource-file-XXXXXX", directory ? directory : "/tmp");
    CHECK(path_length > 0 && (size_t)path_length < sizeof(path));
    int fd = mkstemp(path);
    CHECK(fd >= 0);
    char bytes[16] = "0123456789abcde";
    CHECK(write(fd, bytes, sizeof(bytes)) == sizeof(bytes));
    struct sigaction action = {.sa_handler = file_signal};
    CHECK(sigemptyset(&action.sa_mask) == 0 && sigaction(SIGXFSZ, &action, NULL) == 0);
    struct rlimit limit;
    CHECK(getrlimit(RLIMIT_FSIZE, &limit) == 0);
    limit.rlim_cur = 8;
    CHECK(setrlimit(RLIMIT_FSIZE, &limit) == 0);
    // Existing bytes can be shrunk even when the result remains above the limit.
    CHECK(ftruncate(fd, 12) == 0 && file_signals == 0);
    CHECK(ftruncate(fd, 13) == -1 && errno == EFBIG && file_signals == 1);
    struct stat metadata;
    CHECK(fstat(fd, &metadata) == 0 && metadata.st_size == 12);
    CHECK(ftruncate(fd, 0) == 0 && lseek(fd, 6, SEEK_SET) == 6);
    CHECK(write(fd, bytes, 4) == 2 && file_signals == 1);
    CHECK(write(fd, bytes, 1) == -1 && errno == EFBIG && file_signals == 2);
    CHECK(write(fd, bytes, 0) == 0 && file_signals == 2);
    CHECK(pwrite(fd, bytes, 4, 6) == 2 && lseek(fd, 0, SEEK_CUR) == 8);
    CHECK(file_signals == 2);
    CHECK(lseek(fd, 6, SEEK_SET) == 6);
    struct iovec vectors[] = {{bytes, 2}, {bytes + 2, 2}};
    CHECK(writev(fd, vectors, 2) == 2 && file_signals == 2);
    long page = sysconf(_SC_PAGESIZE);
    CHECK(page > 0);
    void* inaccessible = mmap(NULL, (size_t)page, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(inaccessible != MAP_FAILED);
    CHECK(syscall(SYS_write, fd, inaccessible, 1) == -1 && errno == EFBIG && file_signals == 3);
    CHECK(syscall(SYS_write, fd, (void*)-1, 1) == -1 && errno == EFAULT && file_signals == 3);
    CHECK(munmap(inaccessible, (size_t)page) == 0);
    CHECK(truncate(path, 9) == -1 && errno == EFBIG && file_signals == 4);
    CHECK(fstat(fd, &metadata) == 0 && metadata.st_size == 8);
    const unsigned char expected[8] = {0, 0, 0, 0, 0, 0, '0', '1'};
    unsigned char actual[8];
    CHECK(pread(fd, actual, sizeof(actual), 0) == sizeof(actual) &&
          !memcmp(actual, expected, sizeof(expected)) && fsync(fd) == 0);
    CHECK(fcntl(fd, F_SETFL, O_APPEND) == 0 && lseek(fd, 0, SEEK_SET) == 0);
    CHECK(write(fd, bytes, 1) == -1 && errno == EFBIG && file_signals == 5);
    if (directory) {
        char result[1024];
        int length = snprintf(result, sizeof(result), "%s/resource-file-result", directory);
        CHECK(length > 0 && (size_t)length < sizeof(result));
        CHECK(link(path, result) == 0);
    }
    CHECK(close(fd) == 0 && unlink(path) == 0);
    limit.rlim_cur = 0;
    CHECK(setrlimit(RLIMIT_FSIZE, &limit) == 0);
    int pipefd[2];
    CHECK(pipe(pipefd) == 0 && write(pipefd[1], bytes, 4) == 4);
    char received[4];
    CHECK(read(pipefd[0], received, 4) == 4 && !memcmp(bytes, received, 4));
    CHECK(close(pipefd[0]) == 0 && close(pipefd[1]) == 0 && file_signals == 5);
    fd = open("/dev/null", O_WRONLY);
    CHECK(fd >= 0 && write(fd, bytes, 4) == 4 && close(fd) == 0 && file_signals == 5);
}

static void* hold_thread(void* argument) {
    char byte;
    CHECK(read((int)(intptr_t)argument, &byte, 1) == 1 && byte == 'x');
    return NULL;
}

static void processes(void) {
    struct rlimit limit;
    CHECK(getrlimit(RLIMIT_NPROC, &limit) == 0);
    limit.rlim_cur = 0;
    CHECK(setrlimit(RLIMIT_NPROC, &limit) == 0);
    pid_t child = fork();
    CHECK(child >= 0);
    if (!child)
        _exit(0);
    int status;
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    limit.rlim_cur = 2;
    CHECK(setrlimit(RLIMIT_NPROC, &limit) == 0);
    int pipefd[2];
    CHECK(pipe(pipefd) == 0);
    CHECK(setgroups(0, NULL) == 0 && setgid(67001) == 0 && setuid(67001) == 0);
    CHECK(getuid() == 67001 && geteuid() == 67001);
    child = fork();
    CHECK(child >= 0);
    if (!child)
        _exit(0);
    siginfo_t information;
    CHECK(waitid(P_PID, (id_t)child, &information, WEXITED | WNOWAIT) == 0);
    CHECK(information.si_pid == child && information.si_code == CLD_EXITED);
    CHECK(fork() == -1 && errno == EAGAIN);
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    pthread_t thread;
    CHECK(pthread_create(&thread, NULL, hold_thread, (void*)(intptr_t)pipefd[0]) == 0);
    CHECK(fork() == -1 && errno == EAGAIN);
    CHECK(write(pipefd[1], "x", 1) == 1 && pthread_join(thread, NULL) == 0);
    CHECK(close(pipefd[0]) == 0 && close(pipefd[1]) == 0);
    child = fork();
    CHECK(child >= 0);
    if (!child)
        _exit(0);
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    limit.rlim_cur = 1;
    CHECK(setrlimit(RLIMIT_NPROC, &limit) == 0);
    CHECK(fork() == -1 && errno == EAGAIN);
    CHECK(pthread_create(&thread, NULL, hold_thread, NULL) == EAGAIN);
}

static void process_exec(void) {
    for (unsigned phase = 0; phase < 3; phase++) {
        unsigned flagged = phase == 1;
        int control[2], ready[2];
        pid_t holder = -1;
        if (flagged) {
            CHECK(pipe2(control, O_CLOEXEC) == 0 && pipe2(ready, O_CLOEXEC) == 0);
            holder = fork();
            CHECK(holder >= 0);
            if (!holder) {
                CHECK(close(control[1]) == 0 && close(ready[0]) == 0);
                CHECK(setgid(67004) == 0 && setuid(67004) == 0);
                CHECK(write(ready[1], "r", 1) == 1 && close(ready[1]) == 0);
                char byte;
                CHECK(read(control[0], &byte, 1) >= 0);
                _exit(0);
            }
            CHECK(close(ready[1]) == 0);
            char byte;
            CHECK(read(ready[0], &byte, 1) == 1 && byte == 'r' && close(ready[0]) == 0);
        }
        pid_t child = fork();
        CHECK(child >= 0);
        if (!child) {
            if (flagged)
                CHECK(close(control[0]) == 0 && close(control[1]) == 0);
            struct rlimit limit;
            CHECK(getrlimit(RLIMIT_NPROC, &limit) == 0);
            limit.rlim_cur = 0;
            if (phase)
                CHECK(setrlimit(RLIMIT_NPROC, &limit) == 0);
            CHECK(setgroups(0, NULL) == 0 && setgid(67003 + phase) == 0 &&
                  setuid(67003 + phase) == 0);
            char* const arguments[] = {(char*)executable,
                                       flagged      ? "--verify-flagged-exec"
                                       : phase == 2 ? "--verify-new-uid-zero-exec"
                                                    : "--verify-unflagged-exec",
                                       NULL};
            if (flagged) {
                CHECK(syscall(SYS_execve, executable, (void*)-1, (void*)-1) == -1 &&
                      errno == EAGAIN);
                CHECK(syscall(SYS_execve, (void*)-1, NULL, NULL) == -1 && errno == EFAULT);
                CHECK(syscall(SYS_execve, "", NULL, NULL) == -1 && errno == ENOENT);
                CHECK(execv(executable, arguments) == -1 && errno == EAGAIN);
                limit.rlim_cur = 2;
            }
            CHECK(setrlimit(RLIMIT_NPROC, &limit) == 0);
            execv(executable, arguments);
            CHECK(0);
        }
        int status;
        CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
        if (flagged) {
            CHECK(write(control[1], "x", 1) == 1 && close(control[1]) == 0 &&
                  close(control[0]) == 0);
            CHECK(waitpid(holder, &status, 0) == holder && WIFEXITED(status) &&
                  WEXITSTATUS(status) == 0);
        }
    }
}

static void address_space(void) {
    long page = sysconf(_SC_PAGESIZE);
    CHECK(page > 0);
    unsigned char* held =
        mmap(NULL, (size_t)page * 4, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(held != MAP_FAILED);
    held[0] = 'Q';
    void* slot = held + page;
    CHECK(munmap(slot, (size_t)page * 2) == 0);
    char path[] = "/tmp/resource-map-XXXXXX";
    int file = mkstemp(path);
    CHECK(file >= 0 && ftruncate(file, page) == 0);
    int segment = shmget(IPC_PRIVATE, (size_t)page, IPC_CREAT | 0600);
    CHECK(segment >= 0);
    struct rlimit original, limit;
    CHECK(getrlimit(RLIMIT_AS, &original) == 0);
    limit = original;
    limit.rlim_cur = 0;
    CHECK(setrlimit(RLIMIT_AS, &limit) == 0);
    CHECK(mprotect(held, (size_t)page, PROT_READ | PROT_WRITE) == 0 && held[0] == 'Q');
    CHECK(mmap(NULL, (size_t)page, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0) == MAP_FAILED &&
          errno == ENOMEM);
    CHECK(mmap(NULL, (size_t)page, PROT_READ | PROT_WRITE, MAP_SHARED, file, 0) == MAP_FAILED &&
          errno == ENOMEM);
    uintptr_t old_break = (uintptr_t)syscall(SYS_brk, 0);
    CHECK((uintptr_t)syscall(SYS_brk, old_break + (uintptr_t)page) == old_break);
    CHECK(shmat(segment, NULL, 0) == (void*)-1 && errno == ENOMEM);
    pid_t child = fork();
    CHECK(child >= 0);
    if (!child) {
        struct rlimit inherited;
        CHECK(getrlimit(RLIMIT_AS, &inherited) == 0 && inherited.rlim_cur == 0 && held[0] == 'Q');
        CHECK(mmap(NULL, (size_t)page, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0) ==
                  MAP_FAILED &&
              errno == ENOMEM);
        _exit(0);
    }
    int status;
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    // Discover this actual process's page budget without assuming either loader's footprint.
    size_t low = 0, high = 65536;
    while (low + 1 < high) {
        size_t middle = (low + high) / 2;
        limit.rlim_cur = middle * (size_t)page;
        CHECK(setrlimit(RLIMIT_AS, &limit) == 0);
        void* probe =
            mmap(slot, (size_t)page, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
        if (probe == MAP_FAILED) {
            CHECK(errno == ENOMEM);
            low = middle;
        } else {
            CHECK(munmap(probe, (size_t)page) == 0);
            high = middle;
        }
    }
    limit.rlim_cur = high * (size_t)page;
    CHECK(setrlimit(RLIMIT_AS, &limit) == 0);
    unsigned char* probe = mmap(slot, (size_t)page, PROT_READ | PROT_WRITE,
                                MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    CHECK(probe != MAP_FAILED);
    probe[0] = 'R';
    CHECK(mmap(NULL, (size_t)page, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0) == MAP_FAILED &&
          errno == ENOMEM);
    CHECK(mmap(probe, (size_t)page, PROT_READ, MAP_PRIVATE | MAP_FIXED, -1, 0) == MAP_FAILED &&
          errno == EBADF);
    CHECK(probe[0] == 'R');
    CHECK(mmap(probe, (size_t)page * 2, PROT_READ | PROT_WRITE,
               MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0) == MAP_FAILED &&
          errno == ENOMEM);
    CHECK(probe[0] == 'R');
    CHECK(mmap(probe, (size_t)page, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
               -1, 0) == probe &&
          probe[0] == 0);
    CHECK(munmap(probe, (size_t)page) == 0);
    probe = mmap(slot, (size_t)page, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    CHECK(probe != MAP_FAILED && munmap(probe, (size_t)page) == 0);
    CHECK(setrlimit(RLIMIT_AS, &original) == 0);
    void* shared = shmat(segment, NULL, 0);
    CHECK(shared != (void*)-1 && shmdt(shared) == 0 && shmctl(segment, IPC_RMID, NULL) == 0);
    CHECK(munmap(held, (size_t)page * 4) == 0 && close(file) == 0 && unlink(path) == 0);
}

static void isolated(void (*run)(void), const char* name) {
    pid_t child = fork();
    CHECK(child >= 0);
    if (!child) {
        run();
        _exit(0);
    }
    int status;
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    printf("RESOURCE_LIMIT_OBSERVATION %s\n", name);
    fflush(stdout);
    observations++;
}

static void data_limits(void) {
    size_t page = (size_t)sysconf(_SC_PAGESIZE);
    CHECK(page == 4096);
    unsigned char* held =
        mmap(NULL, page * 4, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(held != MAP_FAILED);
    unsigned char* slot = held + page;
    CHECK(munmap(slot, page * 2) == 0);
    held[0] = 'D';
    char path[] = "/tmp/resource-data-XXXXXX";
    int file = mkstemp(path);
    CHECK(file >= 0 && ftruncate(file, (off_t)page) == 0);
    struct rlimit original, limit;
    CHECK(getrlimit(RLIMIT_DATA, &original) == 0);
    limit = original;
    limit.rlim_cur = 1;
    CHECK(setrlimit(RLIMIT_DATA, &limit) == 0);
    CHECK(mmap(NULL, page, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0) ==
              MAP_FAILED &&
          errno == ENOMEM);
    CHECK(mmap(NULL, page, PROT_READ | PROT_WRITE, MAP_PRIVATE, file, 0) == MAP_FAILED &&
          errno == ENOMEM);
    CHECK(syscall(SYS_mprotect, held + 1, page, PROT_READ | PROT_WRITE) == -1 && errno == EINVAL);
    CHECK(syscall(SYS_mprotect, held, page, PROT_READ | PROT_WRITE | 16) == -1 && errno == EINVAL);
    CHECK(syscall(SYS_mprotect, held, page, PROT_READ | PROT_WRITE | 8) == 0);
    CHECK(syscall(SYS_mprotect, held, page, UINT64_C(1) << 40) == -1 && errno == EINVAL);
    for (unsigned kind = 0; kind < 2; kind++) {
        uint64_t ignored = kind ? UINT64_C(1) << 40 : 16;
        void* mapped = (void*)syscall(SYS_mmap, NULL, page, ignored | PROT_READ,
                                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        CHECK(mapped != MAP_FAILED && munmap(mapped, page) == 0);
        CHECK(syscall(SYS_mmap, NULL, page, ignored | PROT_READ | PROT_WRITE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0) == -1 &&
              errno == ENOMEM);
    }
    void* semantic = mmap(NULL, page, PROT_READ | 8, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(semantic != MAP_FAILED && munmap(semantic, page) == 0);
    CHECK(mprotect(held, page, PROT_READ | PROT_WRITE) == 0 && held[0] == 'D');
    for (unsigned kind = 0; kind < 3; kind++) {
        void* allowed =
            mmap(NULL, page,
                 kind == 2 ? PROT_READ | PROT_WRITE
                 : kind    ? PROT_READ
                           : PROT_NONE,
                 (kind == 2 ? MAP_SHARED : MAP_PRIVATE | MAP_ANONYMOUS), kind == 2 ? file : -1, 0);
        CHECK(allowed != MAP_FAILED && munmap(allowed, page) == 0);
    }
    void* shared = mmap(NULL, page, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    CHECK(shared != MAP_FAILED && munmap(shared, page) == 0);
    void* growing = mmap(NULL, page, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS | MAP_GROWSDOWN, -1, 0);
    CHECK(growing != MAP_FAILED && munmap(growing, page) == 0);
    void* readonly = mmap(NULL, page, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(readonly != MAP_FAILED);
    CHECK(mprotect(readonly, page, PROT_READ | PROT_WRITE) == -1 && errno == ENOMEM);
    struct rlimit address_original, address_zero;
    CHECK(getrlimit(RLIMIT_AS, &address_original) == 0);
    address_zero = address_original;
    address_zero.rlim_cur = 0;
    CHECK(setrlimit(RLIMIT_AS, &address_zero) == 0);
    CHECK(mprotect(readonly, page, PROT_READ | PROT_WRITE) == 0);
    CHECK(setrlimit(RLIMIT_AS, &address_original) == 0 && mprotect(readonly, page, PROT_NONE) == 0);
    uintptr_t old_break = (uintptr_t)syscall(SYS_brk, 0);
    CHECK((uintptr_t)syscall(SYS_brk, old_break + 1) == old_break);
    limit.rlim_cur = 0;
    CHECK(setrlimit(RLIMIT_DATA, &limit) == 0);
    // A zero soft data limit uses the hard limit for mappings, but not brk.
    CHECK(mprotect(readonly, page, PROT_READ | PROT_WRITE) == 0);
    ((unsigned char*)readonly)[0] = 'Z';
    CHECK(munmap(readonly, page) == 0);
    CHECK((uintptr_t)syscall(SYS_brk, old_break + 1) == old_break);
    size_t low = 0, high = 65536;
    while (low + 1 < high) {
        size_t middle = (low + high) / 2;
        limit.rlim_cur = middle * page;
        CHECK(setrlimit(RLIMIT_DATA, &limit) == 0);
        void* probe = mmap(slot, page, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
        if (probe == MAP_FAILED) {
            CHECK(errno == ENOMEM);
            low = middle;
        } else {
            CHECK(munmap(probe, page) == 0);
            high = middle;
        }
    }
    limit.rlim_cur = high * page;
    CHECK(setrlimit(RLIMIT_DATA, &limit) == 0);
    unsigned char* probe =
        mmap(slot, page, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    CHECK(probe == slot);
    probe[0] = 'P';
    CHECK(mmap(NULL, page, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0) ==
              MAP_FAILED &&
          errno == ENOMEM);
    CHECK(mmap(probe, page * 2, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1,
               0) == MAP_FAILED &&
          errno == ENOMEM);
    CHECK(probe[0] == 'P');
    CHECK(mmap(probe, page, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1,
               0) == probe &&
          probe[0] == 0);
    readonly = mmap(NULL, page, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(readonly != MAP_FAILED && mprotect(readonly, page, PROT_READ | PROT_WRITE) == -1 &&
          errno == ENOMEM);
    CHECK(mprotect(probe, page, PROT_READ) == 0);
    CHECK(mprotect(readonly, page, PROT_READ | PROT_WRITE) == 0);
    ((unsigned char*)readonly)[0] = 'R';
    pid_t child = fork();
    CHECK(child >= 0);
    if (!child) {
        struct rlimit inherited;
        CHECK(getrlimit(RLIMIT_DATA, &inherited) == 0 && inherited.rlim_cur == limit.rlim_cur);
        CHECK(mmap(NULL, page, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0) ==
                  MAP_FAILED &&
              errno == ENOMEM);
        _exit(0);
    }
    int status;
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    // Fixed replacement uses net virtual growth for admission, even for a read-only old area.
    CHECK(mmap(probe, page, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1,
               0) == probe);
    CHECK(munmap(probe, page) == 0 && munmap(readonly, page) == 0);
    CHECK(setrlimit(RLIMIT_DATA, &original) == 0);
    uintptr_t anchor = (old_break + page - 1) / page * page + 1;
    CHECK((uintptr_t)syscall(SYS_brk, anchor) == anchor);
    size_t byte_low = 0, byte_high = 256 * 1024 * 1024;
    while (byte_low + 1 < byte_high) {
        size_t middle = (byte_low + byte_high) / 2;
        limit.rlim_cur = middle;
        CHECK(setrlimit(RLIMIT_DATA, &limit) == 0);
        uintptr_t changed = (uintptr_t)syscall(SYS_brk, anchor + 1);
        if (changed == anchor)
            byte_low = middle;
        else {
            CHECK(changed == anchor + 1 && (uintptr_t)syscall(SYS_brk, anchor) == anchor);
            byte_high = middle;
        }
    }
    limit.rlim_cur = byte_high - 1;
    CHECK(setrlimit(RLIMIT_DATA, &limit) == 0 && (uintptr_t)syscall(SYS_brk, anchor + 1) == anchor);
    limit.rlim_cur = byte_high;
    CHECK(setrlimit(RLIMIT_DATA, &limit) == 0 &&
          (uintptr_t)syscall(SYS_brk, anchor + 1) == anchor + 1 &&
          (uintptr_t)syscall(SYS_brk, anchor) == anchor);
    CHECK(setrlimit(RLIMIT_DATA, &original) == 0 &&
          (uintptr_t)syscall(SYS_brk, old_break) == old_break);
    child = fork();
    CHECK(child >= 0);
    if (!child) {
        struct rlimit zero = {0, 0};
        CHECK(setrlimit(RLIMIT_DATA, &zero) == 0);
        CHECK(mmap(NULL, page, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0) ==
                  MAP_FAILED &&
              errno == ENOMEM);
        _exit(0);
    }
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    CHECK(munmap(held, page * 4) == 0 && close(file) == 0 && unlink(path) == 0);
}

__attribute__((noinline)) static void use_main_stack(size_t bytes) {
    volatile unsigned char memory[bytes];
    for (size_t i = 0; i < bytes; i += 4096) {
        memory[i] = (unsigned char)(i / 4096);
        CHECK(memory[i] == (unsigned char)(i / 4096));
    }
    memory[bytes - 1] = 'S';
    CHECK(memory[bytes - 1] == 'S');
}

static void stack_growth_case(unsigned phase) {
    const size_t page = 4096, span = 8 * 1024 * 1024;
    struct rlimit stack = {phase == 15 ? 8 * 1024 * 1024 : 65536, RLIM_INFINITY};
    struct rlimit core = {0, 0};
    CHECK(setrlimit(RLIMIT_STACK, &stack) == 0 && setrlimit(RLIMIT_CORE, &core) == 0);
    if (phase == 15 || phase == 16) {
        use_main_stack(3 * 1024 * 1024);
        return;
    }
    unsigned char* area = mmap(NULL, span, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(area != MAP_FAILED && munmap(area, span) == 0);
    unsigned char* base = area + span / 2;
    size_t initial = phase == 7 ? 32 * page : phase == 18 || phase == 19 ? 4 * page : page;
    int protection = phase == 6 ? PROT_NONE : phase == 13 ? PROT_READ : PROT_READ | PROT_WRITE;
    CHECK(mmap(base, initial, protection,
               MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS | (phase == 17 ? 0 : MAP_GROWSDOWN), -1,
               0) == base);
    if (phase == 17) {
        CHECK(mprotect(base, page, PROT_READ | 0x1000000) == -1 && errno == EINVAL);
        return;
    }
    if (phase == 18 || phase == 19) {
        CHECK(mprotect(base + page, page, PROT_READ | 0x1000000) == 0);
        if (phase == 18) {
            base[0] = 'F';
            _exit(95);
        }
        base[3 * page] = 'U';
        CHECK(base[3 * page] == 'U' && *(volatile unsigned char*)(base - page) == 0);
        return;
    }
    if (phase == 20) {
        CHECK(syscall(SYS_mprotect, 0, 0, 0x1000000) == 0);
        CHECK(syscall(SYS_mprotect, 0, 0, 0x2000000) == 0);
        CHECK(syscall(SYS_mprotect, 0, 0, 16) == 0);
        CHECK(syscall(SYS_mprotect, 0, 0, 0x3000000) == -1 && errno == EINVAL);
        CHECK(mprotect(base, page, PROT_READ | 0x2000000) == -1 && errno == EINVAL);
        return;
    }
    if (phase == 21) {
        CHECK(mprotect(base - page, page * 2, PROT_READ | 0x1000000) == 0);
        CHECK(*(volatile unsigned char*)(base - page) == 0);
        return;
    }
    size_t down = phase == 1 ? 15 : phase == 2 ? 16 : 1;
    if (phase == 3) {
        struct rlimit data = {1, RLIM_INFINITY};
        CHECK(setrlimit(RLIMIT_DATA, &data) == 0);
    }
    if (phase == 4) {
        struct rlimit address = {1, RLIM_INFINITY};
        CHECK(setrlimit(RLIMIT_AS, &address) == 0);
    }
    if (phase == 5) {
        stack.rlim_cur = 0;
        CHECK(setrlimit(RLIMIT_STACK, &stack) == 0);
        base[0] = 'I';
    }
    if (phase == 8)
        CHECK(mprotect(base, page, PROT_READ) == 0);
    if (phase == 9)
        CHECK(munmap(base, initial) == 0);
    if (phase == 10) {
        stack.rlim_cur = RLIM_INFINITY;
        CHECK(setrlimit(RLIMIT_STACK, &stack) == 0);
        down = 512;
    }
    if (phase == 11 || phase == 12)
        CHECK(mmap(base - 2 * page, page, phase == 11 ? PROT_READ | PROT_WRITE : PROT_NONE,
                   MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0) == base - 2 * page);
    volatile unsigned char* target = base - down * page;
    if (phase == 13) {
        CHECK(*target == 0);
        return;
    }
    if (phase == 14) {
        int descriptors[2];
        CHECK(pipe(descriptors) == 0 && write(descriptors[1], "K", 1) == 1);
        CHECK(read(descriptors[0], (void*)target, 1) == 1 && *target == 'K');
        CHECK(close(descriptors[0]) == 0 && close(descriptors[1]) == 0);
        return;
    }
    *target = 'G';
    CHECK(*target == 'G');
}

static void stack_limits(void) {
    struct rlimit initial;
    CHECK(getrlimit(RLIMIT_STACK, &initial) == 0 && initial.rlim_cur == 8 * 1024 * 1024 &&
          initial.rlim_max == RLIM_INFINITY);
    for (unsigned phase = 0; phase < 22; phase++) {
        pid_t child = fork();
        CHECK(child >= 0);
        if (!child) {
            stack_growth_case(phase);
            _exit(0);
        }
        int status;
        CHECK(waitpid(child, &status, 0) == child);
        int denied =
            phase == 2 || (phase >= 4 && phase <= 9) || phase == 11 || phase == 16 || phase == 18;
        CHECK(denied ? WIFSIGNALED(status) && WTERMSIG(status) == SIGSEGV
                     : WIFEXITED(status) && WEXITSTATUS(status) == 0);
    }
    const rlim_t limits[] = {65536, 524288, 8388608, RLIM_INFINITY};
    const size_t sizes[] = {32768, 126976, 262144, 2097152, 6291456};
    for (unsigned limit = 0; limit < 4; limit++)
        for (unsigned size = 0; size < 5; size++) {
            pid_t child = fork();
            CHECK(child >= 0);
            if (!child) {
                char limit_text[32], size_text[32];
                CHECK(snprintf(limit_text, sizeof(limit_text), "%llu",
                               (unsigned long long)limits[limit]) > 0);
                CHECK(snprintf(size_text, sizeof(size_text), "%zu", sizes[size]) > 0);
                char* arguments[128] = {(char*)executable, "--verify-stack-exec", limit_text,
                                        size_text};
                size_t remaining = sizes[size], count = 4;
                while (remaining) {
                    size_t bytes = remaining < 60000 ? remaining : 60000;
                    char* value = mmap(NULL, bytes, PROT_READ | PROT_WRITE,
                                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
                    CHECK(value != MAP_FAILED && count + 1 < 128);
                    memset(value, 'x', bytes - 1);
                    value[bytes - 1] = 0;
                    arguments[count++] = value;
                    remaining -= bytes;
                }
                struct rlimit stack = {limits[limit], RLIM_INFINITY}, core = {0, 0};
                CHECK(setrlimit(RLIMIT_STACK, &stack) == 0 && setrlimit(RLIMIT_CORE, &core) == 0);
                char* environment[] = {"PATH=/bin", NULL};
                execve(executable, arguments, environment);
                CHECK(errno == E2BIG);
                _exit(23);
            }
            int status;
            CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status));
            int accepted = limit == 0   ? size == 0
                           : limit == 1 ? size <= 1
                           : limit == 2 ? size <= 2
                                        : size <= 3;
            CHECK(WEXITSTATUS(status) == (accepted ? 0 : 23));
        }
}

static uint64_t cpu_clock(clockid_t clock) {
    struct timespec value;
    CHECK(syscall(SYS_clock_gettime, clock, &value) == 0 && value.tv_sec >= 0 &&
          value.tv_nsec >= 0 && value.tv_nsec < 1000000000);
    return (uint64_t)value.tv_sec * 1000000000 + (uint64_t)value.tv_nsec;
}

static void cpu_burn(uint64_t duration) {
    uint64_t start = cpu_clock(CLOCK_THREAD_CPUTIME_ID);
    uint64_t wall = cpu_clock(CLOCK_MONOTONIC);
    volatile uint64_t work = 1;
    while (cpu_clock(CLOCK_THREAD_CPUTIME_ID) - start < duration) {
        for (unsigned i = 0; i < 4096; i++)
            work = work * 1664525 + 1013904223;
        CHECK(cpu_clock(CLOCK_MONOTONIC) - wall < 15000000000ull);
    }
}

struct CpuThread {
    uint64_t initial, elapsed, duration;
};

static void* cpu_worker(void* argument) {
    struct CpuThread* result = argument;
    result->initial = cpu_clock(CLOCK_THREAD_CPUTIME_ID);
    cpu_burn(result->duration);
    result->elapsed = cpu_clock(CLOCK_THREAD_CPUTIME_ID) - result->initial;
    return NULL;
}

struct CpuSignal {
    uint64_t nanoseconds, soft, hard;
    int signal;
};

static int cpu_signal_pipe;

static void cpu_signal(int signal) {
    struct timespec now;
    struct rlimit limit;
    if (syscall(SYS_clock_gettime, CLOCK_PROCESS_CPUTIME_ID, &now) ||
        syscall(SYS_getrlimit, RLIMIT_CPU, &limit))
        _exit(91);
    struct CpuSignal record = {(uint64_t)now.tv_sec * 1000000000 + (uint64_t)now.tv_nsec,
                               limit.rlim_cur, limit.rlim_max, signal};
    if (write(cpu_signal_pipe, &record, sizeof(record)) != sizeof(record))
        _exit(92);
}

static void cpu_zero_signal(int signal) {
    _exit(signal == SIGXCPU ? 0 : 93);
}

static void cpu_forever(void) {
    volatile uint64_t value = 1;
    for (;;)
        value = value * 1664525 + 1013904223;
}

static void cpu_limits(void) {
    uint64_t before = cpu_clock(CLOCK_PROCESS_CPUTIME_ID);
    uint64_t thread_before = cpu_clock(CLOCK_THREAD_CPUTIME_ID);
    uint64_t wall = cpu_clock(CLOCK_MONOTONIC);
    struct timespec pause = {0, 250000000};
    CHECK(nanosleep(&pause, NULL) == 0);
    CHECK(cpu_clock(CLOCK_MONOTONIC) - wall >= 240000000);
    CHECK(cpu_clock(CLOCK_PROCESS_CPUTIME_ID) - before < 100000000 &&
          cpu_clock(CLOCK_THREAD_CPUTIME_ID) - thread_before < 100000000);
    CHECK(syscall(SYS_clock_gettime, CLOCK_PROCESS_CPUTIME_ID, NULL) == -1 && errno == EFAULT);
    cpu_burn(250000000);
    CHECK(cpu_clock(CLOCK_PROCESS_CPUTIME_ID) >= before + 240000000);
    pid_t child = fork();
    CHECK(child >= 0);
    if (!child) {
        CHECK(cpu_clock(CLOCK_PROCESS_CPUTIME_ID) < 100000000 &&
              cpu_clock(CLOCK_THREAD_CPUTIME_ID) < 100000000);
        _exit(0);
    }
    int status;
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    struct CpuThread worker = {0, 0, 250000000};
    pthread_t thread;
    before = cpu_clock(CLOCK_PROCESS_CPUTIME_ID);
    thread_before = cpu_clock(CLOCK_THREAD_CPUTIME_ID);
    CHECK(pthread_create(&thread, NULL, cpu_worker, &worker) == 0 &&
          pthread_join(thread, NULL) == 0);
    CHECK(worker.initial < 100000000 && worker.elapsed >= 240000000 &&
          cpu_clock(CLOCK_PROCESS_CPUTIME_ID) - before >= 240000000 &&
          cpu_clock(CLOCK_THREAD_CPUTIME_ID) - thread_before < 100000000);
    child = fork();
    CHECK(child >= 0);
    if (!child) {
        cpu_burn(250000000);
        struct rlimit limit = {7, 8};
        CHECK(setrlimit(RLIMIT_CPU, &limit) == 0);
        char* arguments[] = {(char*)executable, "--verify-cpu-exec", NULL};
        execv(executable, arguments);
        CHECK(0);
    }
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    int descriptors[2];
    CHECK(pipe(descriptors) == 0);
    child = fork();
    CHECK(child >= 0);
    if (!child) {
        CHECK(close(descriptors[0]) == 0);
        cpu_signal_pipe = descriptors[1];
        struct sigaction action = {0};
        action.sa_handler = cpu_signal;
        CHECK(sigemptyset(&action.sa_mask) == 0 && sigaction(SIGXCPU, &action, NULL) == 0);
        struct rlimit limit = {1, 3};
        CHECK(setrlimit(RLIMIT_CPU, &limit) == 0);
        cpu_forever();
    }
    CHECK(close(descriptors[1]) == 0);
    struct CpuSignal signals[3];
    size_t received = 0;
    ssize_t count;
    while ((count = read(descriptors[0], (unsigned char*)signals + received,
                         sizeof(signals) - received)) > 0) {
        received += (size_t)count;
        CHECK(received < sizeof(signals));
    }
    CHECK(count == 0 && received == 2 * sizeof(signals[0]) && close(descriptors[0]) == 0);
    CHECK(waitpid(child, &status, 0) == child && WIFSIGNALED(status) &&
          WTERMSIG(status) == SIGKILL);
    for (unsigned i = 0; i < 2; i++) {
        fprintf(stderr, "RESOURCE_CPU_SIGNAL index=%u signal=%d ns=%llu soft=%llu hard=%llu\n", i,
                signals[i].signal, (unsigned long long)signals[i].nanoseconds,
                (unsigned long long)signals[i].soft, (unsigned long long)signals[i].hard);
        CHECK(signals[i].signal == SIGXCPU && signals[i].soft == i + 2 && signals[i].hard == 3 &&
              signals[i].nanoseconds >= (uint64_t)(i + 1) * 1000000000 - 250000000 &&
              signals[i].nanoseconds < (uint64_t)(i + 1) * 1000000000 + 500000000);
    }
    child = fork();
    CHECK(child >= 0);
    if (!child) {
        struct sigaction action = {0};
        action.sa_handler = cpu_zero_signal;
        CHECK(sigemptyset(&action.sa_mask) == 0 && sigaction(SIGXCPU, &action, NULL) == 0);
        struct rlimit limit = {0, 1};
        CHECK(setrlimit(RLIMIT_CPU, &limit) == 0);
        cpu_forever();
    }
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    child = fork();
    CHECK(child >= 0);
    if (!child) {
        struct rlimit limit = {0, 0};
        CHECK(setrlimit(RLIMIT_CPU, &limit) == 0);
        cpu_forever();
    }
    CHECK(waitpid(child, &status, 0) == child && WIFSIGNALED(status) &&
          WTERMSIG(status) == SIGKILL);
    child = fork();
    CHECK(child >= 0);
    if (!child) {
        struct rlimit limit = {1, 1};
        CHECK(setrlimit(RLIMIT_CPU, &limit) == 0);
        struct CpuThread work[2] = {{0, 0, 700000000}, {0, 0, 700000000}};
        pthread_t workers[2];
        CHECK(pthread_create(&workers[0], NULL, cpu_worker, &work[0]) == 0 &&
              pthread_create(&workers[1], NULL, cpu_worker, &work[1]) == 0);
        CHECK(pthread_join(workers[0], NULL) == 0 && pthread_join(workers[1], NULL) == 0);
        _exit(94);
    }
    CHECK(waitpid(child, &status, 0) == child && WIFSIGNALED(status) &&
          WTERMSIG(status) == SIGKILL);
    CHECK(pipe(descriptors) == 0);
    child = fork();
    CHECK(child >= 0);
    if (!child) {
        CHECK(close(descriptors[0]) == 0);
        struct rlimit limit = {1, 1};
        CHECK(setrlimit(RLIMIT_CPU, &limit) == 0);
        pause = (struct timespec){1, 250000000};
        CHECK(nanosleep(&pause, NULL) == 0 && write(descriptors[1], "S", 1) == 1);
        cpu_forever();
    }
    CHECK(close(descriptors[1]) == 0);
    char slept;
    CHECK(read(descriptors[0], &slept, 1) == 1 && slept == 'S' && close(descriptors[0]) == 0);
    CHECK(waitpid(child, &status, 0) == child && WIFSIGNALED(status) &&
          WTERMSIG(status) == SIGKILL);
}

int main(int argc, char** argv) {
    if (argc >= 4 && !strcmp(argv[1], "--verify-stack-exec")) {
        struct rlimit limit;
        CHECK(getrlimit(RLIMIT_STACK, &limit) == 0 &&
              limit.rlim_cur == (rlim_t)strtoull(argv[2], NULL, 10) &&
              limit.rlim_max == RLIM_INFINITY);
        size_t bytes = 0;
        for (int i = 4; i < argc; i++)
            bytes += strlen(argv[i]) + 1;
        CHECK(bytes == (size_t)strtoull(argv[3], NULL, 10));
        return 0;
    }
    if (argc == 2 && !strcmp(argv[1], "--verify-cpu-exec")) {
        struct rlimit limit;
        CHECK(getrlimit(RLIMIT_CPU, &limit) == 0 && limit.rlim_cur == 7 && limit.rlim_max == 8);
        CHECK(cpu_clock(CLOCK_PROCESS_CPUTIME_ID) >= 240000000);
        return 0;
    }
    if (argc == 2 &&
        (!strcmp(argv[1], "--verify-flagged-exec") || !strcmp(argv[1], "--verify-unflagged-exec") ||
         !strcmp(argv[1], "--verify-new-uid-zero-exec"))) {
        int flagged = !strcmp(argv[1], "--verify-flagged-exec");
        int new_uid_zero = !strcmp(argv[1], "--verify-new-uid-zero-exec");
        struct rlimit limit;
        CHECK(getuid() == (uid_t)(67003 + flagged + 2 * new_uid_zero) &&
              getrlimit(RLIMIT_NPROC, &limit) == 0);
        if (limit.rlim_cur != (rlim_t)(flagged ? 2 : 0))
            fprintf(stderr, "RESOURCE_EXEC_LIMIT uid=%u flagged=%d soft=%llu hard=%llu\n", getuid(),
                    flagged, (unsigned long long)limit.rlim_cur,
                    (unsigned long long)limit.rlim_max);
        CHECK(limit.rlim_cur == (rlim_t)(flagged ? 2 : 0));
        return 0;
    }
    if (argc == 2 && !strcmp(argv[1], "--verify-exec")) {
        CHECK(nofile().rlim_cur == 14);
        return 0;
    }
    CHECK((argc == 1 || (argc == 2 && !strcmp(argv[1], "--native"))) && geteuid() == 0);
    executable = argv[0];
    isolated(interface, "raw_abi_fault_precedence_aliasing_and_hard_limit_permissions");
    isolated(descriptors, "real_descriptor_pressure_pipe_rollback_and_retained_high_descriptions");
    isolated(lifetime, "thread_group_sharing_fork_copy_and_actual_exec_preservation");
    isolated(file_size,
             "real_file_size_partial_scalar_vector_positioned_append_signal_and_truncate");
    isolated(processes, "real_uid_process_thread_zombie_quotas_root_exemption_and_reclamation");
    isolated(process_exec, "real_uid_change_deferred_exec_denial_recheck_and_unflagged_exec");
    isolated(address_space,
             "actual_address_space_budget_none_shared_brk_fork_fixed_replacement_and_reclamation");
    isolated(cpu_limits,
             "actual_process_thread_cpu_idle_fork_exec_soft_repetition_and_hard_termination");
    isolated(data_limits,
             "actual_private_data_mappings_protection_fixed_admission_and_byte_heap_limits");
    isolated(stack_limits, "actual_stack_fault_growth_guard_copy_and_exec_argument_budgets");
    printf("RESOURCE_LIMIT_PASS observations=%u "
           "scope=interface-descriptors-files-processes-exec-memory-cpu-data-stack\n",
           observations);
    return 0;
}
