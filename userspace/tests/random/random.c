// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/random.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef RANDOM_LINKAGE
#define RANDOM_LINKAGE "static"
#endif

static void check(int value, const char* reason) {
    if (!value) {
        fprintf(stderr, "RANDOM_TEST_FAIL %s errno=%d\n", reason, errno);
        exit(1);
    }
}

static void pause_ms(unsigned ms) {
    struct timespec duration = {ms / 1000, (long)(ms % 1000) * 1000000};
    check(nanosleep(&duration, NULL) == 0, "bounded observer sleep");
}

static void read_all(int fd, void* data, size_t size) {
    size_t done = 0;
    while (done < size) {
        ssize_t count = read(fd, (uint8_t*)data + done, size - done);
        check(count > 0 && (size_t)count <= size - done, "complete pipe/device read");
        done += count;
    }
}

static int entropy(int fd) {
    int count = -1;
    check(ioctl(fd, 0x80045200, &count) == 0, "RNDGETENTCNT");
    return count;
}

static void flags(void) {
    uint8_t bytes[16];
    check(getrandom(bytes, sizeof(bytes), 8) == -1 && errno == EINVAL, "unknown flag");
    check(getrandom(bytes, sizeof(bytes), 6) == -1 && errno == EINVAL, "insecure plus random");
    check(getrandom(bytes, sizeof(bytes), 7) == -1 && errno == EINVAL, "all three flags");
    check(getentropy(bytes, 257) == -1 && errno == EIO, "getentropy length limit");
    puts("RANDOM_FLAGS_PASS unknown=EINVAL incompatible=EINVAL getentropy_limit=EIO");
}

static int event_fd;
static volatile sig_atomic_t caught;

static void notified(int signal) {
    (void)signal;
    caught++;
    (void)write(event_fd, "H", 1);
}

static void interrupted(const char* operation, int restart) {
    int events[2], status;
    check(pipe(events) == 0, "wait observer pipe");
    pid_t child = fork();
    check(child >= 0, "actual blocked child");
    if (!child) {
        close(events[0]);
        event_fd = events[1];
        caught = 0;
        struct sigaction action = {.sa_handler = notified, .sa_flags = restart ? SA_RESTART : 0};
        sigemptyset(&action.sa_mask);
        check(sigaction(SIGUSR1, &action, NULL) == 0, "first interrupt handler");
        action.sa_flags = 0;
        check(sigaction(SIGUSR2, &action, NULL) == 0, "final interrupt handler");
        int fd = -1;
        if (!strcmp(operation, "device") || !strcmp(operation, "device-zero")) {
            fd = open("/dev/random", O_RDONLY);
            check(fd >= 0, "blocking random device");
        }
        check(write(event_fd, "R", 1) == 1, "wait observer ready");
        uint8_t bytes[16];
        ssize_t result =
            fd >= 0 ? read(fd, bytes, !strcmp(operation, "device-zero") ? 0 : sizeof(bytes))
            : !strcmp(operation, "getentropy") ? getentropy(bytes, sizeof(bytes))
                                               : getrandom(bytes, sizeof(bytes), 0);
        check(result == -1 && errno == EINTR && caught == (restart ? 2 : 1),
              "interrupted uninitialized operation");
        if (fd >= 0)
            check(close(fd) == 0, "blocked device cleanup");
        _exit(0);
    }
    close(events[1]);
    char marker;
    read_all(events[0], &marker, 1);
    check(marker == 'R', "child entered initialization wait");
    pause_ms(50);
    check(waitpid(child, &status, WNOHANG) == 0, "unready operation remains blocked");
    check(kill(child, SIGUSR1) == 0, "signal blocked child");
    read_all(events[0], &marker, 1);
    check(marker == 'H', "actual handler ran");
    if (restart) {
        pause_ms(50);
        check(waitpid(child, &status, WNOHANG) == 0, "SA_RESTART resumes initialization wait");
        check(kill(child, SIGUSR2) == 0, "nonrestart signal ends resumed wait");
    }
    int libc_retry = !strcmp(operation, "getentropy");
    if (libc_retry) {
        if (restart) {
            read_all(events[0], &marker, 1);
            check(marker == 'H', "libc observed final signal");
        }
        pause_ms(50);
        check(waitpid(child, &status, WNOHANG) == 0, "musl getentropy retries EINTR internally");
        check(kill(child, SIGKILL) == 0, "finish the intentionally waiting libc client");
    }
    check(waitpid(child, &status, 0) == child &&
              (libc_retry ? WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL
                          : WIFEXITED(status) && WEXITSTATUS(status) == 0),
          "checked blocked-client exit");
    check(close(events[0]) == 0, "wait observer cleanup");
    printf("RANDOM_WAIT_PASS operation=%s restart=%d result=%s observer=progress\n", operation,
           restart, libc_retry ? "retry" : "EINTR");
}

static void unready(int random_fd, int urandom_fd) {
    uint8_t bytes[256], previous[256];
    check(entropy(random_fd) == 0, "unready entropy count");
    check(getrandom(bytes, 16, GRND_NONBLOCK) == -1 && errno == EAGAIN,
          "unready nonblocking request");
    check(getrandom((void*)1, 16, GRND_NONBLOCK) == -1 && errno == EAGAIN,
          "readiness checked before copying");
    check(getrandom(NULL, 0, GRND_NONBLOCK) == -1 && errno == EAGAIN,
          "zero-length initialized request still observes readiness");
    check(read(random_fd, bytes, 16) == -1 && errno == EAGAIN, "nonblocking random device");
    check(read(random_fd, NULL, 0) == -1 && errno == EAGAIN,
          "zero-length random device read still observes readiness");
    check(read(random_fd, (void*)UINTPTR_MAX, 0) == -1 && errno == EFAULT,
          "zero-length device destination remains a user address");
    check(read(urandom_fd, NULL, 0) == 0, "zero-length early urandom read");
    struct iovec empty = {NULL, 0};
    check(readv(random_fd, &empty, 1) == 0 && readv(random_fd, NULL, 0) == 0,
          "empty readv completes before device dispatch");
    struct pollfd both[] = {{random_fd, POLLIN | POLLOUT, 0}, {urandom_fd, POLLIN, 0}};
    check(poll(both, 2, 0) == 2 && !(both[0].revents & POLLIN) && (both[0].revents & POLLOUT) &&
              (both[1].revents & POLLIN),
          "unready random poll and early urandom readability");
    check(getrandom(bytes, sizeof(bytes), 4 | GRND_NONBLOCK) == sizeof(bytes),
          "explicit insecure getrandom");
    memcpy(previous, bytes, sizeof(bytes));
    check(read(urandom_fd, bytes, sizeof(bytes)) == sizeof(bytes) &&
              memcmp(bytes, previous, sizeof(bytes)) && entropy(random_fd) == 0,
          "early urandom advances state without crediting it");
    check(write(random_fd, bytes, sizeof(bytes)) == sizeof(bytes) &&
              write(urandom_fd, previous, sizeof(previous)) == sizeof(previous) &&
              entropy(random_fd) == 0,
          "ordinary device writes never establish readiness");
    const char* operations[] = {"getrandom", "getentropy", "device", "device-zero"};
    for (unsigned operation = 0; operation < sizeof(operations) / sizeof(operations[0]);
         operation++)
        for (int restart = 0; restart <= 1; restart++)
            interrupted(operations[operation], restart);
    check(entropy(random_fd) == 0, "signals and elapsed time never credit entropy");
    puts("RANDOM_UNREADY_PASS nonblock=EAGAIN writes=uncredited insecure=explicit poll=checked");
}

static void concurrent(void) {
    int channel[2];
    pid_t children[8];
    uint8_t samples[8][32];
    check(pipe(channel) == 0, "concurrent source pipe");
    for (unsigned i = 0; i < 8; i++) {
        children[i] = fork();
        check(children[i] >= 0, "eight actual random readers");
        if (!children[i]) {
            close(channel[0]);
            uint8_t sample[32];
            check(getrandom(sample, sizeof(sample), 0) == sizeof(sample) &&
                      write(channel[1], sample, sizeof(sample)) == sizeof(sample),
                  "child generated and published sample");
            _exit(0);
        }
    }
    close(channel[1]);
    read_all(channel[0], samples, sizeof(samples));
    check(close(channel[0]) == 0, "concurrent pipe cleanup");
    for (unsigned i = 0; i < 8; i++) {
        int status;
        check(waitpid(children[i], &status, 0) == children[i] && WIFEXITED(status) &&
                  WEXITSTATUS(status) == 0,
              "checked actual reader exit");
        for (unsigned earlier = 0; earlier < i; earlier++)
            check(memcmp(samples[i], samples[earlier], 32), "shared generator survives fork");
    }
    puts("RANDOM_CONCURRENT_PASS processes=8 samples=distinct");
}

static void ready(int random_fd, int urandom_fd) {
    uint8_t bytes[8192], previous[32];
    check(entropy(random_fd) == 256, "trusted seed established readiness");
    check(read(random_fd, NULL, 0) == 0 && read(urandom_fd, NULL, 0) == 0,
          "zero-length initialized device reads");
    check(read(random_fd, (void*)UINTPTR_MAX, 0) == -1 && errno == EFAULT,
          "initialized empty read still validates the user address");
    const unsigned valid[] = {0, 1, 2, 3, 4, 5};
    for (unsigned i = 0; i < sizeof(valid) / sizeof(valid[0]); i++)
        check(getrandom(bytes, 256, valid[i]) == 256, "all valid flags return a full small read");
    check(getrandom(NULL, 0, 0) == 0 && getentropy(bytes, 256) == 0, "ready libc getentropy");
    check(syscall(SYS_getrandom, bytes, 16, (UINT64_C(1) << 32) | GRND_NONBLOCK) == 16,
          "flags have Linux unsigned-int width");
    check(getrandom((void*)1, 16, 0) == -1 && errno == EFAULT, "getrandom bad user pointer");
    check(getrandom((void*)UINTPTR_MAX, 0, 0) == -1 && errno == EFAULT,
          "zero-length destination still has a user address");
    check(syscall(SYS_getrandom, (void*)UINT64_C(0x7fffffffff00), 512, 0) == -1 && errno == EFAULT,
          "destination range stays below the user limit");
    uint8_t* pages = mmap(NULL, 8192, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    check(pages != MAP_FAILED && mprotect(pages + 4096, 4096, PROT_NONE) == 0,
          "guard-page fixture");
    check(getrandom(pages + 4096 - 256, 512, 0) == 256, "partial result before later copy fault");
    check(munmap(pages, 8192) == 0, "guard-page cleanup");
    size_t done = 0;
    while (done < sizeof(bytes)) {
        ssize_t count = getrandom(bytes + done, sizeof(bytes) - done, 0);
        check(count > 0 && (size_t)count <= sizeof(bytes) - done, "checked large short reads");
        done += count;
    }
    struct pollfd polled = {random_fd, POLLIN | POLLOUT, 0};
    check(poll(&polled, 1, 0) == 1 && (polled.revents & POLLIN) && !(polled.revents & POLLOUT),
          "initialized random poll readiness");
    read_all(random_fd, bytes, 1024);
    read_all(urandom_fd, bytes + 1024, 1024);
    check(memcmp(bytes, bytes + 1024, 1024), "both random devices consume shared fresh output");
    const uint8_t* auxiliary = (const uint8_t*)getauxval(AT_RANDOM);
    check(auxiliary && memcmp(auxiliary, bytes, 16), "process AT_RANDOM supplied separately");
    memcpy(previous, bytes, sizeof(previous));
    check(write(random_fd, bytes, sizeof(bytes)) == sizeof(bytes) && entropy(random_fd) == 256 &&
              getrandom(bytes, sizeof(previous), 0) == sizeof(previous) &&
              memcmp(bytes, previous, sizeof(previous)),
          "uncredited input mixing preserves initialized generator");
    printf("RANDOM_SAMPLE linkage=%s value=", RANDOM_LINKAGE);
    for (unsigned i = 0; i < 32; i++)
        printf("%02x", bytes[i]);
    putchar('\n');
    concurrent();
    puts("RANDOM_READY_PASS flags=6 copies=checked devices=shared auxv=shared libc=checked");
}

int main(int argc, char** argv) {
    check(argc == 2 && (!strcmp(argv[1], "ready") || !strcmp(argv[1], "ready-reseed") ||
                        !strcmp(argv[1], "unready")),
          "fixture mode");
    flags();
    int random_fd = open("/dev/random", O_RDWR | O_NONBLOCK);
    int urandom_fd = open("/dev/urandom", O_RDWR | O_NONBLOCK);
    check(random_fd >= 0 && urandom_fd >= 0, "both real random devices");
    int count;
    check(ioctl(random_fd, 0x80045200, (void*)1) == -1 && errno == EFAULT,
          "ioctl user-copy failure");
    check(ioctl(random_fd, 0x40085203, &count) == -1 && errno == EOPNOTSUPP,
          "unimplemented credited-seed administration stays explicit");
    if (strcmp(argv[1], "unready"))
        ready(random_fd, urandom_fd);
    else
        unready(random_fd, urandom_fd);
    if (!strcmp(argv[1], "ready-reseed")) {
        struct timespec before, after;
        uint8_t bytes[32];
        check(clock_gettime(CLOCK_MONOTONIC, &before) == 0, "reseed observer start");
        pause_ms(62000);
        check(clock_gettime(CLOCK_MONOTONIC, &after) == 0 && entropy(random_fd) == 256 &&
                  getrandom(bytes, sizeof(bytes), GRND_NONBLOCK) == sizeof(bytes),
              "initialized output after the periodic source refresh");
        uint64_t elapsed =
            (uint64_t)(after.tv_sec - before.tv_sec) * 1000000000 + after.tv_nsec - before.tv_nsec;
        check(elapsed >= UINT64_C(62000000000), "reseed interval observer actually elapsed");
        printf("RANDOM_RESEED_CLIENT_PASS elapsed_ns=%llu ready=preserved\n",
               (unsigned long long)elapsed);
    }
    check(close(random_fd) == 0 && close(urandom_fd) == 0, "random descriptors close");
    printf("RANDOM_TEST_PASS linkage=%s mode=%s\n", RANDOM_LINKAGE, argv[1]);
}
