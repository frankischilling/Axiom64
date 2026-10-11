// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/random.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef RANDOM_LINKAGE
#define RANDOM_LINKAGE "native"
#endif

enum {
    get_count = 0x80045200u,
    add_count = 0x40045201u,
    add_entropy = 0x40085203u,
    zap_count = 0x5204u,
    clear_pool = 0x5206u,
    reseed = 0x5207u
};

static unsigned observations;

static void check(int condition, const char* reason) {
    if (!condition) {
        fprintf(stderr, "RANDOM_ADMIN_FAIL case=%s errno=%d\n", reason, errno);
        exit(1);
    }
}

static void command(int fd, const char* label, unsigned request, void* data, int error) {
    errno = 0;
    int result = ioctl(fd, request, data);
    int actual_error = result == -1 ? errno : 0;
    printf("RANDOM_ADMIN_OBSERVATION case=%s request=%08x result=%d error=%d\n", label, request,
           result, actual_error);
    observations++;
    check(result == (error ? -1 : 0) && actual_error == error, label);
}

static int entropy(int fd) {
    int count = -1;
    command(fd, "get-count", get_count, &count, 0);
    check(count >= 0 && count <= 256, "bounded initialization count");
    printf("RANDOM_ADMIN_COUNT bits=%d\n", count);
    return count;
}

static void denied(int fd) {
    unsigned requests[] = {add_count, add_entropy, zap_count, clear_pool, reseed};
    for (unsigned i = 0; i < sizeof(requests) / sizeof(requests[0]); i++)
        command(fd, "capability-before-pointer", requests[i], (void*)1, EPERM);
    command(fd, "unknown-command", 0xdeadbeefu, NULL, EINVAL);
    (void)entropy(fd);
}

static void controls(int fd, int initial) {
    int count = 0;
    command(fd, "zero-credit", add_count, &count, 0);
    count = -1;
    command(fd, "negative-credit", add_count, &count, EINVAL);
    command(fd, "bad-credit-pointer", add_count, (void*)1, EFAULT);
    command(fd, "bad-entropy-pointer", add_entropy, (void*)1, EFAULT);
    int empty[2] = {0, 0};
    command(fd, "empty-uncredited-input", add_entropy, empty, 0);
    command(fd, "zap-is-noop", zap_count, (void*)1, 0);
    command(fd, "clear-is-noop", clear_pool, (void*)1, 0);
    check(entropy(fd) == initial, "control operations preserve count");
    command(fd, "reseed-readiness", reseed, (void*)1, initial == 256 ? 0 : ENODATA);

    uint8_t* pages = mmap(NULL, 8192, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    check(pages != MAP_FAILED && mprotect(pages + 4096, 4096, PROT_NONE) == 0,
          "guarded input mapping");
    count = -1;
    memcpy(pages + 4092, &count, sizeof(count));
    command(fd, "negative-count-before-second-copy", add_entropy, pages + 4092, EINVAL);
    count = 0;
    memcpy(pages + 4092, &count, sizeof(count));
    command(fd, "second-word-copy-fault", add_entropy, pages + 4092, EFAULT);
    int header[2] = {0, -1};
    memcpy(pages + 4064, header, sizeof(header));
    memset(pages + 4072, 0x5a, 24);
    command(fd, "negative-buffer-length", add_entropy, pages + 4064, EFAULT);
    header[0] = 256;
    header[1] = 40;
    memcpy(pages + 4064, header, sizeof(header));
    command(fd, "partial-copy-never-credits", add_entropy, pages + 4064, EFAULT);
    check(entropy(fd) == initial, "copy failures preserve credit");
    header[0] = 0;
    header[1] = 24;
    memcpy(pages + 4064, header, sizeof(header));
    command(fd, "complete-uncredited-input", add_entropy, pages + 4064, 0);
    check(entropy(fd) == initial, "ordinary mixing has no credit");
    check(munmap(pages, 8192) == 0, "guarded input cleanup");
}

static void bootstrap(int fd, int count_only) {
    uint8_t bytes[32];
    check(entropy(fd) == 0, "fresh uninitialized kernel");
    if (count_only) {
        int count = INT_MAX;
        command(fd, "administrator-count-assertion-clamps", add_count, &count, 0);
    } else {
        int count = 1;
        command(fd, "first-partial-bit", add_count, &count, 0);
        check(entropy(fd) == 1, "partial count one");
        count = 127;
        command(fd, "partial-credit-accumulates", add_count, &count, 0);
        check(entropy(fd) == 128 && getrandom(bytes, sizeof(bytes), GRND_NONBLOCK) == -1 &&
                  errno == EAGAIN,
              "partial count does not initialize");
        int empty[2] = {127, 0};
        command(fd, "administrator-empty-input-assertion", add_entropy, empty, 0);
        check(entropy(fd) == 255 && getrandom(bytes, sizeof(bytes), GRND_NONBLOCK) == -1 &&
                  errno == EAGAIN,
              "threshold remains unmet");

        struct {
            int count, length;
            uint8_t bytes[32];
        } seed = {1, 32, {0}};

        for (unsigned i = 0; i < sizeof(seed.bytes); i++)
            seed.bytes[i] = i;
        // Deliberately known data in an isolated policy fixture, never a trusted source.
        command(fd, "administrator-completes-threshold", add_entropy, &seed, 0);
    }
    check(entropy(fd) == 256 && getrandom(bytes, sizeof(bytes), GRND_NONBLOCK) == sizeof(bytes),
          "administrator assertion wakes initialized interface");
    int count = INT_MAX;
    command(fd, "initialized-count-stays-bounded", add_count, &count, 0);
    command(fd, "initialized-zap-is-noop", zap_count, NULL, 0);
    command(fd, "initialized-clear-is-noop", clear_pool, NULL, 0);
    command(fd, "initialized-reseed", reseed, NULL, 0);
    check(entropy(fd) == 256, "initialized state is monotonic");
    printf("RANDOM_ADMIN_BOOTSTRAP_PASS count_only=%d policy_fixture=known-input\n", count_only);
}

static void drop_administrator(int fd) {
    pid_t child = fork();
    check(child >= 0, "capability child");
    if (!child) {
        struct {
            uint32_t version;
            int pid;
        } header = {0x20080522u, 0};

        struct {
            uint32_t effective, permitted, inheritable;
        } data[2];

        check(syscall(SYS_capget, &header, data) == 0 && (data[0].effective & (1u << 21)),
              "initial administrative capability");
        check(prctl(PR_CAPBSET_DROP, 21, 0, 0, 0) == 0, "irreversible bounding-set drop");
        data[0].effective &= ~(1u << 21);
        data[0].permitted &= ~(1u << 21);
        data[0].inheritable &= ~(1u << 21);
        check(syscall(SYS_capset, &header, data) == 0 && geteuid() == 0,
              "root identity without administrative capability");
        denied(fd);
        puts("RANDOM_ADMIN_CAPABILITY_PASS uid=0 administrative_capability=absent");
        fflush(stdout);
        _exit(0);
    }
    int status;
    check(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0,
          "capability child exit");
}

int main(int argc, char** argv) {
    check(argc == 2 && (!strcmp(argv[1], "ready") || !strcmp(argv[1], "denied") ||
                        !strcmp(argv[1], "bootstrap") || !strcmp(argv[1], "count-bootstrap")),
          "fixture mode");
    setbuf(stdout, NULL);
    int random_fd = open("/dev/random", O_RDWR | O_NONBLOCK);
    int urandom_fd = open("/dev/urandom", O_RDWR | O_NONBLOCK);
    check(random_fd >= 0 && urandom_fd >= 0, "both random devices");
    int initial = entropy(random_fd);
    check(initial ==
              (!strcmp(argv[1], "bootstrap") || !strcmp(argv[1], "count-bootstrap") ? 0 : 256),
          "expected initial readiness");
    for (unsigned i = 0; i < 2; i++) {
        int fd = i ? urandom_fd : random_fd;
        command(fd, "bad-count-destination", get_count, (void*)1, EFAULT);
        command(fd, "removed-pool-command", 0x80085202u, NULL, EINVAL);
        command(fd, "unknown-command", 0xdeadbeefu, NULL, EINVAL);
        int count = -1;
        check(syscall(SYS_ioctl, fd, (UINT64_C(1) << 32) | get_count, &count) == 0 &&
                  count == initial,
              "ioctl command has unsigned-int width");
        if (!strcmp(argv[1], "denied"))
            denied(fd);
        else
            controls(fd, initial);
    }
    if (!strcmp(argv[1], "bootstrap") || !strcmp(argv[1], "count-bootstrap"))
        bootstrap(random_fd, !strcmp(argv[1], "count-bootstrap"));
    if (strcmp(argv[1], "denied"))
        drop_administrator(random_fd);
    check(close(random_fd) == 0 && close(urandom_fd) == 0, "description cleanup");
    printf("RANDOM_ADMIN_PASS linkage=%s mode=%s observations=%u\n", RANDOM_LINKAGE, argv[1],
           observations);
    return 0;
}
