// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>

static const char* path = "/proc/sys/net/ipv4/igmp_max_msf";
static unsigned operations;

struct expected {
    const char* label;
    long result;
    int error;
    long offset, value;
    int open_error;
    const char* hex;
};
static const struct expected expected[] = {
    {"empty", 0, 0, 0, 17, -1, NULL},
    {"zero", 1, 0, 1, 0, -1, NULL},
    {"ten", 2, 0, 2, 10, -1, NULL},
    {"sixty-four", 3, 0, 3, 64, -1, NULL},
    {"sixty-five", 2, 0, 2, 65, -1, NULL},
    {"negative", 2, 0, 2, -1, -1, NULL},
    {"minimum", 11, 0, 11, -2147483648, -1, NULL},
    {"maximum", 10, 0, 10, 2147483647, -1, NULL},
    {"positive-overflow", -1, 22, 0, 17, -1, NULL},
    {"negative-overflow", -1, 22, 0, 17, -1, NULL},
    {"octal", 3, 0, 3, 8, -1, NULL},
    {"hex", 4, 0, 4, 64, -1, NULL},
    {"upper-hex", 4, 0, 4, 64, -1, NULL},
    {"invalid-octal", -1, 22, 0, 17, -1, NULL},
    {"empty-hex", -1, 22, 0, 17, -1, NULL},
    {"bad-hex-tail", -1, 22, 0, 17, -1, NULL},
    {"plus", -1, 22, 0, 17, -1, NULL},
    {"negative-hex", 4, 0, 4, -1, -1, NULL},
    {"negative-octal", 4, 0, 4, -8, -1, NULL},
    {"negative-zero", 2, 0, 2, 0, -1, NULL},
    {"spaces", 4, 0, 4, 64, -1, NULL},
    {"all-space", -1, 22, 0, 17, -1, NULL},
    {"leading-cr", 3, 0, 3, 64, -1, NULL},
    {"trailing-cr", -1, 22, 0, 17, -1, NULL},
    {"separated-cr", 4, 0, 4, 64, -1, NULL},
    {"leading-vtab", 3, 0, 3, 64, -1, NULL},
    {"trailing-vtab", -1, 22, 0, 17, -1, NULL},
    {"separated-vtab", 4, 0, 4, 64, -1, NULL},
    {"two-values", 3, 0, 3, 64, -1, NULL},
    {"newline-tail", 3, 0, 3, 64, -1, NULL},
    {"space-tail", 3, 0, 3, 64, -1, NULL},
    {"attached-tail", -1, 22, 0, 17, -1, NULL},
    {"negative-sign", -1, 22, 0, 17, -1, NULL},
    {"twenty-zeroes", 20, 0, 20, 0, -1, NULL},
    {"twenty-one-zeroes", -1, 22, 0, 17, -1, NULL},
    {"zero-delimiter", -1, 22, 0, 17, -1, NULL},
    {"nonzero-offset-valid", 3, 0, 4, 17, -1, NULL},
    {"nonzero-offset-invalid", 3, 0, 4, 17, -1, NULL},
    {"positioned-zero", 3, 0, 5, 64, -1, NULL},
    {"positioned-one", 3, 0, 5, 17, -1, NULL},
    {"append", 3, 0, 3, 64, -1, NULL},
    {"all-space-beyond-page", -1, 22, 0, 17, -1, NULL},
    {"valid-prefix-beyond-page", 4100, 0, 4100, 64, -1, NULL},
    {"page-edge-value", 4096, 0, 4096, 64, -1, NULL},
    {"partial-read", 1, 0, 1, 17, -1, "31"},
    {"partial-read-eof", 0, 0, 1, 17, -1, ""},
    {"zero-read", 0, 0, 1, 17, -1, ""},
    {"positioned-full-read", 3, 0, 1, 17, -1, "31370a"},
    {"positioned-offset-read", 0, 0, 1, 17, -1, ""},
    {"ordinary-open", -2, 0, -1, 17, 13, NULL},
    {"root-group-open", -2, 0, -1, 17, 13, NULL},
    {"ordinary-inherited-descriptor", -1, 1, -1, 17, 0, NULL},
};

static void verify(const char* label, long result, int error, long offset, long value,
                   int open_error, const char* bytes) {
    int good = operations < sizeof(expected) / sizeof(expected[0]);
    const struct expected* e = good ? &expected[operations] : &expected[0];
    good = good && !strcmp(e->label, label) && result == e->result && error == e->error &&
           value == e->value && (e->offset < 0 || offset == e->offset) &&
           (e->open_error < 0 || open_error == e->open_error);
    if (good && e->hex) {
        size_t count = result > 0 ? (size_t)result : 0;
        good = strlen(e->hex) == count * 2;
        for (size_t n = 0; good && n < count; n++) {
            char pair[3];
            snprintf(pair, sizeof(pair), "%02x", (unsigned char)bytes[n]);
            good = !memcmp(pair, e->hex + n * 2, 2);
        }
    }
    if (!good) {
        fprintf(stderr,
                "IPV4_SOURCE_POLICY_FAIL operation=%u label=%s result=%ld errno=%d offset=%ld "
                "value=%ld open_errno=%d\n",
                operations, label, result, error, offset, value, open_error);
        exit(1);
    }
    operations++;
}

static void need(int value, const char* message) {
    if (!value) {
        perror(message);
        exit(1);
    }
}

static long current(void) {
    char bytes[64] = {0};
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    need(fd >= 0, "read open");
    ssize_t count = read(fd, bytes, sizeof(bytes) - 1);
    need(count > 0 && bytes[count - 1] == '\n', "read value");
    close(fd);
    return strtol(bytes, NULL, 10);
}

static void set(long value) {
    char bytes[64];
    int length = snprintf(bytes, sizeof(bytes), "%ld\n", value);
    int fd = open(path, O_WRONLY | O_CLOEXEC);
    need(fd >= 0, "reset open");
    need(write(fd, bytes, (size_t)length) == length, "reset write");
    close(fd);
    need(current() == value, "reset readback");
}

static void writing(const char* label, const void* bytes, size_t length, off_t start,
                    int positioned, int flags) {
    set(17);
    int fd = open(path, O_RDWR | O_CLOEXEC | flags);
    need(fd >= 0, "case open");
    need(lseek(fd, start, SEEK_SET) == start, "case seek");
    errno = 0;
    ssize_t result =
        positioned ? pwrite(fd, bytes, length, positioned == 1 ? 0 : 1) : write(fd, bytes, length);
    int error = result < 0 ? errno : 0;
    off_t offset = lseek(fd, 0, SEEK_CUR);
    close(fd);
    printf("{\"label\":\"%s\",\"result\":%ld,\"errno\":%d,\"offset\":%ld,\"value\":%ld}\n", label,
           (long)result, error, (long)offset, current());
    verify(label, (long)result, error, (long)offset, current(), -1, NULL);
}

static void reading(const char* label, int fd, size_t length, int positioned, off_t at) {
    char bytes[64] = {0};
    errno = 0;
    ssize_t result = positioned ? pread(fd, bytes, length, at) : read(fd, bytes, length);
    int error = result < 0 ? errno : 0;
    off_t offset = lseek(fd, 0, SEEK_CUR);
    printf("{\"label\":\"%s\",\"result\":%ld,\"errno\":%d,\"offset\":%ld,\"hex\":\"", label,
           (long)result, error, (long)offset);
    for (ssize_t n = 0; n < result; n++)
        printf("%02x", (unsigned char)bytes[n]);
    printf("\",\"value\":%ld}\n", current());
    verify(label, (long)result, error, (long)offset, current(), -1, bytes);
}

static void ordinary(const char* label, gid_t group, int inherited) {
    set(17);
    int inherited_fd = inherited ? open(path, O_WRONLY | O_CLOEXEC) : -1;
    need(!inherited || inherited_fd >= 0, "inherited open");
    pid_t child = fork();
    need(child >= 0, "fork");
    if (!child) {
        need(setgroups(0, NULL) == 0 && setgid(group) == 0 && setuid(1000) == 0,
             "ordinary identity");
        errno = 0;
        int fd = inherited ? inherited_fd : open(path, O_WRONLY | O_CLOEXEC);
        int open_error = fd < 0 ? errno : 0;
        errno = 0;
        ssize_t result = fd < 0 ? -2 : write(fd, "64\n", 3);
        int error = result == -1 ? errno : 0;
        if (fd >= 0)
            close(fd);
        printf("{\"label\":\"%s\",\"open_errno\":%d,\"result\":%ld,\"errno\":%d,\"value\":%ld}\n",
               label, open_error, (long)result, error, current());
        verify(label, (long)result, error, -1, current(), open_error, NULL);
        fflush(stdout);
        _exit(0);
    }
    if (inherited_fd >= 0)
        close(inherited_fd);
    int status;
    need(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0,
         "ordinary wait");
    need(current() == 17, "ordinary unchanged");
    operations++;
}

int main(int argc, char** argv) {
    struct utsname kernel;
    need(uname(&kernel) == 0, "actual execution kernel");
    int native = !strcmp(kernel.sysname, "Linux");
    need(argc == 1 || (argc == 2 && native && !strcmp(argv[1], "--native")),
         "known execution mode");
    setvbuf(stdout, NULL, _IOLBF, 0);
    if (native) {
        char parent[128], own[128];
        ssize_t a = readlink("/proc/self/ns/net", parent, sizeof(parent));
        need(a > 0 && unshare(CLONE_NEWNET) == 0, "owned network namespace");
        ssize_t b = readlink("/proc/self/ns/net", own, sizeof(own));
        need(b > 0 && (a != b || memcmp(parent, own, (size_t)a)), "different namespace");
    }
    struct stat status;
    need(stat(path, &status) == 0, "policy identity");
    long original = current();
    need(original == 10 && (status.st_mode & 07777) == 0644 && !status.st_uid && !status.st_gid,
         "original policy default and permissions");
    printf("{\"kernel\":\"%s\",\"native\":%s,\"owned_namespace\":%s,\"default\":%ld,\"mode\":%u,"
           "\"uid\":%u,\"gid\":%u}\n",
           kernel.release, native ? "true" : "false", native ? "true" : "false", original,
           (unsigned)(status.st_mode & 07777), (unsigned)status.st_uid, (unsigned)status.st_gid);

    struct token {
        const char* name;
        const char* text;
    } tokens[] = {{"empty", ""},
                  {"zero", "0"},
                  {"ten", "10"},
                  {"sixty-four", "64\n"},
                  {"sixty-five", "65"},
                  {"negative", "-1"},
                  {"minimum", "-2147483648"},
                  {"maximum", "2147483647"},
                  {"positive-overflow", "2147483648"},
                  {"negative-overflow", "-2147483649"},
                  {"octal", "010"},
                  {"hex", "0x40"},
                  {"upper-hex", "0X40"},
                  {"invalid-octal", "08"},
                  {"empty-hex", "0x"},
                  {"bad-hex-tail", "0x1g"},
                  {"plus", "+1"},
                  {"negative-hex", "-0x1"},
                  {"negative-octal", "-010"},
                  {"negative-zero", "-0"},
                  {"spaces", " 64 "},
                  {"all-space", " \t\r\n"},
                  {"leading-cr", "\r64"},
                  {"trailing-cr", "64\r"},
                  {"separated-cr", "64 \r"},
                  {"leading-vtab", "\v64"},
                  {"trailing-vtab", "64\v"},
                  {"separated-vtab", "64 \v"},
                  {"two-values", "64 65"},
                  {"newline-tail", "64\njunk"},
                  {"space-tail", "64 junk"},
                  {"attached-tail", "64junk"},
                  {"negative-sign", "-"},
                  {"twenty-zeroes", "00000000000000000000"},
                  {"twenty-one-zeroes", "000000000000000000000"}};

    for (size_t n = 0; n < sizeof(tokens) / sizeof(tokens[0]); n++)
        writing(tokens[n].name, tokens[n].text, strlen(tokens[n].text), 0, 0, 0);
    const char zero[] = {'6', '4', 0};
    writing("zero-delimiter", zero, sizeof(zero), 0, 0, 0);
    writing("nonzero-offset-valid", "64\n", 3, 1, 0, 0);
    writing("nonzero-offset-invalid", "bad", 3, 1, 0, 0);
    writing("positioned-zero", "64\n", 3, 5, 1, 0);
    writing("positioned-one", "64\n", 3, 5, 2, 0);
    writing("append", "64\n", 3, 0, 0, O_APPEND);
    char large[8192];
    memset(large, ' ', sizeof(large));
    writing("all-space-beyond-page", large, sizeof(large), 0, 0, 0);
    memcpy(large, "64 ", 3);
    memset(large + 3, 'x', sizeof(large) - 3);
    writing("valid-prefix-beyond-page", large, sizeof(large), 0, 0, 0);
    memset(large, ' ', sizeof(large));
    memcpy(large + 4093, "64 ", 3);
    writing("page-edge-value", large, 4096, 0, 0, 0);
    set(17);
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    need(fd >= 0, "read cases open");
    reading("partial-read", fd, 1, 0, 0);
    reading("partial-read-eof", fd, 63, 0, 0);
    reading("zero-read", fd, 0, 0, 0);
    reading("positioned-full-read", fd, 63, 1, 0);
    reading("positioned-offset-read", fd, 63, 1, 1);
    close(fd);
    ordinary("ordinary-open", 1000, 0);
    ordinary("root-group-open", 0, 0);
    ordinary("ordinary-inherited-descriptor", 1000, 1);
    set(original);
    need(operations == sizeof(expected) / sizeof(expected[0]), "complete policy operations");
    printf("IPV4 SOURCE POLICY PASS operations=%u\n", operations);
    return 0;
}
