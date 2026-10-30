// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>

static const char* nodes[] = {"conf/all/accept_source_route",
                              "conf/default/accept_source_route",
                              "conf/lo/accept_source_route",
                              "conf/all/forwarding",
                              "conf/default/forwarding",
                              "conf/lo/forwarding",
                              "ip_forward"};
static unsigned observations;

static void require(int condition, const char* operation) {
    if (!condition) {
        printf("IPV4_SOURCE_CONTROLS_FAIL operation=%s errno=%d case=%u\n", operation, errno,
               observations);
        exit(1);
    }
}

static int open_node(unsigned node, int flags) {
    char path[128];
    int size = snprintf(path, sizeof(path), "/proc/sys/net/ipv4/%s", nodes[node]);
    require(size > 0 && (size_t)size < sizeof(path), "node-path");
    return open(path, flags | O_CLOEXEC);
}

static void values(int32_t output[7]) {
    for (unsigned node = 0; node < 7; node++) {
        char text[32];
        int fd = open_node(node, O_RDONLY);
        require(fd >= 0, "read-open");
        ssize_t size = read(fd, text, sizeof(text) - 1);
        require(size > 0 && (size_t)size < sizeof(text) && close(fd) == 0, "read-value");
        text[size] = 0;
        char* end;
        errno = 0;
        long value = strtol(text, &end, 10);
        require(!errno && value >= INT32_MIN && value <= INT32_MAX && !strcmp(end, "\n"),
                "integer-value");
        output[node] = (int32_t)value;
    }
}

static void reset(void) {
    // Establish a host policy explicitly; a new Linux namespace may inherit forwarding.
    const char* selected[] = {"0\n", "1\n", "1\n", "0\n", "0\n", "0\n", "0\n"};
    for (unsigned node = 0; node < 7; node++) {
        int fd = open_node(node, O_WRONLY);
        require(fd >= 0, "reset-open");
        require(write(fd, selected[node], 2) == 2 && close(fd) == 0, "reset-write");
    }
}

static void record(unsigned node, const unsigned char* input, size_t length, ssize_t result,
                   int error, off_t offset, const char* kind) {
    int32_t actual[7];
    values(actual);
    char hex[65];
    require(length <= 32, "bounded-input");
    for (size_t n = 0; n < length; n++) {
        hex[2 * n] = "0123456789abcdef"[input[n] >> 4];
        hex[2 * n + 1] = "0123456789abcdef"[input[n] & 15];
    }
    hex[2 * length] = 0;
    char text[768];
    int size =
        snprintf(text, sizeof(text),
                 "{\"kind\":\"%s\",\"case\":%u,\"node\":%u,\"input\":\"%s\","
                 "\"result\":%ld,\"errno\":%d,\"position\":%lld,"
                 "\"values\":[%d,%d,%d,%d,%d,%d,%d]}\n",
                 kind, observations++, node, hex, (long)result, error, (long long)offset, actual[0],
                 actual[1], actual[2], actual[3], actual[4], actual[5], actual[6]);
    require(size > 0 && (size_t)size < sizeof(text), "bounded-record");
    require(write(STDOUT_FILENO, text, (size_t)size) == size, "complete-record");
}

static void writes(void) {
    const char* inputs[] = {
        "0\n",          "1\n",           "2\n",          "-1\n",  "2147483647\n", "-2147483648\n",
        "2147483648\n", "-2147483649\n", "1 trailing\n", " 1 \n", "\n",           "",
        "word\n",       "+1\n",          "0x10\n",       "010\n", "1 2\n",        "1\t2\n"};
    for (unsigned node = 0; node < 7; node++) {
        reset();
        for (unsigned n = 0; n < sizeof(inputs) / sizeof(inputs[0]); n++) {
            int fd = open_node(node, O_WRONLY);
            require(fd >= 0, "write-open");
            errno = 0;
            ssize_t result = write(fd, inputs[n], strlen(inputs[n]));
            int error = result < 0 ? errno : 0;
            off_t offset = lseek(fd, 0, SEEK_CUR);
            require(offset >= 0 && close(fd) == 0, "write-offset");
            record(node, (const unsigned char*)inputs[n], strlen(inputs[n]), result, error, offset,
                   "write");
        }
        int fd = open_node(node, O_WRONLY);
        require(fd >= 0 && lseek(fd, 1, SEEK_SET) == 1, "positioned-open");
        errno = 0;
        ssize_t result = write(fd, "0\n", 2);
        int error = result < 0 ? errno : 0;
        off_t offset = lseek(fd, 0, SEEK_CUR);
        require(offset >= 0 && close(fd) == 0, "positioned-close");
        record(node, (const unsigned char*)"0\n", 2, result, error, offset, "positioned");
    }
}

static void aliases(void) {
    // Unchanged global writes must preserve an independently changed link or default.
    static const struct {
        unsigned node;
        const char* value;
    } steps[] = {{6, "1\n"}, {5, "0\n"}, {6, "1\n"}, {3, "2\n"}, {4, "-1\n"}, {3, "2\n"},
                 {6, "0\n"}, {4, "3\n"}, {5, "4\n"}, {6, "0\n"}, {6, "-1\n"}, {0, "1\n"},
                 {1, "0\n"}, {6, "1\n"}, {2, "0\n"}, {0, "0\n"}, {0, "1\n"}};

    reset();
    for (unsigned n = 0; n < sizeof(steps) / sizeof(steps[0]); n++) {
        int fd = open_node(steps[n].node, O_WRONLY);
        require(fd >= 0, "alias-open");
        size_t length = strlen(steps[n].value);
        errno = 0;
        ssize_t result = write(fd, steps[n].value, length);
        int error = result < 0 ? errno : 0;
        off_t offset = lseek(fd, 0, SEEK_CUR);
        require(offset >= 0 && close(fd) == 0, "alias-close");
        record(steps[n].node, (const unsigned char*)steps[n].value, length, result, error, offset,
               "alias");
    }
}

struct child_result {
    ssize_t result;
    int error;
    off_t offset;
};

static void inherited(void) {
    for (unsigned node = 0; node < 7; node++) {
        reset();
        int fd = open_node(node, O_WRONLY), channel[2];
        require(fd >= 0 && pipe2(channel, O_CLOEXEC) == 0, "inherited-open");
        pid_t pid = fork();
        require(pid >= 0, "inherited-fork");
        if (!pid) {
            close(channel[0]);
            if (setgroups(0, NULL) || setresgid(65534, 65534, 65534) ||
                setresuid(65534, 65534, 65534))
                _exit(2);
            errno = 0;
            struct child_result value = {0};
            value.result = write(fd, "1\n", 2);
            value.error = value.result < 0 ? errno : 0;
            value.offset = lseek(fd, 0, SEEK_CUR);
            _exit(write(channel[1], &value, sizeof(value)) == (ssize_t)sizeof(value) ? 0 : 3);
        }
        close(channel[1]);
        struct child_result value;
        require(read(channel[0], &value, sizeof(value)) == (ssize_t)sizeof(value),
                "inherited-result");
        int status;
        require(waitpid(pid, &status, 0) == pid && status == 0, "inherited-exit");
        require(close(channel[0]) == 0 && close(fd) == 0, "inherited-close");
        record(node, (const unsigned char*)"1\n", 2, value.result, value.error, value.offset,
               "inherited");
    }
}

int main(void) {
    struct utsname kernel;
    require(uname(&kernel) == 0 && geteuid() == 0, "privileged-kernel-identity");
    if (!strcmp(kernel.sysname, "Linux")) {
        const char* parent = getenv("IPV4_SOURCE_PARENT_NETNS");
        struct stat own;
        require(parent && stat("/proc/self/ns/net", &own) == 0 &&
                    own.st_ino != (ino_t)strtoull(parent, NULL, 10),
                "private-native-network-namespace");
        const char* barrier = getenv("IPV4_SOURCE_RUNTIME_FD");
        unsigned char release;
        require(barrier && read(atoi(barrier), &release, 1) == 1 && release == 0xa5 &&
                    close(atoi(barrier)) == 0,
                "captured-native-runtime");
    } else
        require(!strcmp(kernel.sysname, "Axiom64"), "supported-kernel");
    printf("IPV4_SOURCE_CONTROLS_KERNEL sysname=%s release=%s\n", kernel.sysname, kernel.release);
    fflush(stdout);
    writes();
    inherited();
    aliases();
    reset();
    printf("IPV4_SOURCE_CONTROLS_PASS observations=%u\n", observations);
    return 0;
}
