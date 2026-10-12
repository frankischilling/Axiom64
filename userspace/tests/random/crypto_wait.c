// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

static void require(int condition, const char* operation) {
    if (!condition) {
        fprintf(stderr, "CRYPTO_WAIT_FAIL operation=%s error=%d\n", operation, errno);
        exit(1);
    }
}

static long long now(void) {
    struct timespec value;
    require(clock_gettime(CLOCK_MONOTONIC, &value) == 0, "monotonic clock");
    return (long long)value.tv_sec * 1000000000 + value.tv_nsec;
}

static void sleep_ms(unsigned milliseconds) {
    struct timespec value = {milliseconds / 1000, (milliseconds % 1000) * 1000000};
    while (nanosleep(&value, &value) < 0)
        require(errno == EINTR, "real elapsed sleep");
}

static int credit(void) {
    int fd = open("/dev/random", O_RDONLY | O_CLOEXEC), result = -1;
    require(fd >= 0 && ioctl(fd, 0x80045200U, &result) == 0 && close(fd) == 0, "entropy count");
    return result;
}

static void unready(void) {
    unsigned char byte;
    require(credit() == 0, "no credit before initialization");
    errno = 0;
    require(getrandom(&byte, 1, GRND_NONBLOCK) == -1 && errno == EAGAIN,
            "nonblocking readiness error");
}

int main(int argc, char** argv) {
    require(argc == 4, "mode executable output arguments");
    int ready = !strcmp(argv[1], "ready") || !strcmp(argv[1], "virtio");
    int administrative = !strcmp(argv[1], "administrative");
    require(ready || administrative || !strcmp(argv[1], "absent") || !strcmp(argv[1], "untrusted"),
            "supported source mode");
    require(access(argv[3], F_OK) == -1 && errno == ENOENT, "fresh output path");
    if (!ready) {
        unready();
        struct termios terminal;
        require(tcgetattr(0, &terminal) == 0, "serial terminal state");
        cfmakeraw(&terminal);
        require(tcsetattr(0, TCSANOW, &terminal) == 0, "raw serial observation barrier");
    }
    pid_t child = fork();
    require(child >= 0, "real client fork");
    if (!child) {
        execl(argv[2], argv[2], "rand", "-out", argv[3], "32", (char*)0);
        _exit(127);
    }
    printf("CRYPTO_WAIT_START mode=%s pid=%d\n", argv[1], child);
    fflush(stdout);
    int status = -1;
    if (!ready) {
        unsigned char observation;
        require(read(0, &observation, 1) == 1 && observation == 'B',
                "host observed blocked OS read");
        long long started = now();
        while (now() - started < 500000000) {
            require(waitpid(child, &status, WNOHANG) == 0, "real client remains pending");
            sleep_ms(10);
        }
        unready();
        struct stat value;
        errno = 0;
        int result = stat(argv[3], &value);
        require((result == 0 && value.st_size == 0) || (result == -1 && errno == ENOENT),
                "no random output before initialization");
        printf("CRYPTO_WAIT_BLOCKED mode=%s pid=%d elapsed_ns=%lld credit=0\n", argv[1], child,
               now() - started);
        fflush(stdout);
        if (!administrative) {
            require(kill(child, SIGTERM) == 0, "pending real client signal");
            require(waitpid(child, &status, 0) == child && WIFSIGNALED(status) &&
                        WTERMSIG(status) == SIGTERM,
                    "real client signal status");
            unready();
            printf("CRYPTO_WAIT_PASS mode=%s signal=%d credit=0\n", argv[1], WTERMSIG(status));
            return 0;
        }

        struct {
            int entropy_count, buffer_size;
            unsigned char data[32];
        } seed = {256, 32, {0}};

        char hex[64];
        size_t received = 0;
        while (received < sizeof(hex)) {
            ssize_t count = read(0, hex + received, sizeof(hex) - received);
            require(count > 0, "fresh native OS entropy transport");
            received += count;
        }
        for (unsigned at = 0; at < sizeof(seed.data); at++) {
            unsigned value = 0;
            for (unsigned digit = 0; digit < 2; digit++) {
                unsigned char c = hex[at * 2 + digit];
                require((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'),
                        "trusted entropy encoding");
                value = value * 16 + (c <= '9' ? c - '0' : c - 'a' + 10);
            }
            seed.data[at] = value;
        }
        int fd = open("/dev/random", O_RDONLY | O_CLOEXEC);
        require(fd >= 0 && ioctl(fd, 0x40085203U, &seed) == 0 && close(fd) == 0,
                "authorized real entropy initialization");
        memset(seed.data, 0, sizeof(seed.data));
        memset(hex, 0, sizeof(hex));
        puts("CRYPTO_ADMIN_INITIALIZED source=native-os credited_bits=256");
    }
    long long deadline = now() + 10000000000LL;
    pid_t result;
    while ((result = waitpid(child, &status, WNOHANG)) == 0 && now() < deadline)
        sleep_ms(10);
    require(result == child && WIFEXITED(status) && WEXITSTATUS(status) == 0,
            "initialized real client result");
    unsigned char value[32];
    int fd = open(argv[3], O_RDONLY | O_CLOEXEC);
    struct stat metadata;
    require(fd >= 0 && fstat(fd, &metadata) == 0 && S_ISREG(metadata.st_mode) &&
                metadata.st_size == 32,
            "complete real random output");
    require(read(fd, value, sizeof(value)) == sizeof(value) && close(fd) == 0,
            "real random output bytes");
    char hex[65];
    for (unsigned at = 0; at < sizeof(value); at++)
        snprintf(hex + at * 2, 3, "%02x", value[at]);
    require(credit() >= 256, "initialized generator credit");
    printf("CRYPTO_WAIT_OUTPUT mode=%s bytes=32 hex=%s\n", argv[1], hex);
    printf("CRYPTO_WAIT_PASS mode=%s status=0 credit=%d\n", argv[1], credit());
    return 0;
}
