// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <linux/capability.h>
#include <net/if.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>

static const char* directory = "/proc/sys/net/ipv6/conf/eth0/";
static unsigned count;

static void must(int condition) {
    if (!condition) {
        printf("SYSCTL_IO_FATAL errno=%d\n", errno);
        exit(90);
    }
}

static int open_setting(const char* name, int flags) {
    char path[256];
    snprintf(path, sizeof(path), "%s%s", directory, name);
    return open(path, flags | O_CLOEXEC);
}

static int current(const char* name) {
    int fd = open_setting(name, O_RDONLY);
    must(fd >= 0);
    char bytes[64];
    ssize_t length = read(fd, bytes, sizeof(bytes) - 1);
    must(length > 0);
    bytes[length] = 0;
    must(close(fd) == 0);
    return atoi(bytes);
}

static void write_value(const char* label, const char* name, const char* value) {
    int fd = open_setting(name, O_WRONLY);
    must(fd >= 0);
    errno = 0;
    ssize_t result = write(fd, value, strlen(value));
    int error = result < 0 ? errno : 0;
    must(close(fd) == 0);
    printf("IO_WRITE label=%s name=%s result=%ld error=%d value=%d\n", label, name, (long)result,
           error, current(name));
    count++;
}

static void read_part(const char* label, int fd, size_t size) {
    unsigned char bytes[64] = {0};
    errno = 0;
    ssize_t result = read(fd, bytes, size);
    int error = result < 0 ? errno : 0;
    printf("IO_READ label=%s result=%ld error=%d bytes=", label, (long)result, error);
    for (ssize_t at = 0; at < result; at++)
        printf("%02x", bytes[at]);
    printf("\n");
    count++;
}

static void vector_result(const char* label, int fd, const struct iovec* vectors, int count) {
    errno = 0;
    ssize_t result = writev(fd, vectors, count);
    int error = result < 0 ? errno : 0;
    printf("IO_VECTOR label=%s result=%ld error=%d offset=%ld value=%d\n", label, (long)result,
           error, (long)lseek(fd, 0, SEEK_CUR), current("addr_gen_mode"));
}

static void capability_child(int inherited, int administrator) {
    struct __user_cap_header_struct header = {_LINUX_CAPABILITY_VERSION_3, 0};
    struct __user_cap_data_struct data[2] = {{0}, {0}};
    must(syscall(SYS_capget, &header, data) == 0);
    if (administrator) {
        must(prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0) == 0 && setgid(65534) == 0 && setuid(65534) == 0);
        memset(data, 0, sizeof(data));
        data[0].effective = data[0].permitted = 1u << CAP_NET_ADMIN;
    } else {
        data[0].effective &= ~(1u << CAP_NET_ADMIN);
        data[0].permitted &= ~(1u << CAP_NET_ADMIN);
    }
    must(syscall(SYS_capset, &header, data) == 0);
    errno = 0;
    int fd = open_setting("addr_gen_mode", O_WRONLY);
    int error = fd < 0 ? errno : 0;
    printf("IO_CAP_OPEN administrator=%d uid=%u result=%d error=%d\n", administrator,
           (unsigned)getuid(), fd >= 0, error);
    if (fd >= 0)
        must(close(fd) == 0);
    for (unsigned at = 0; at < 3; at++) {
        errno = 0;
        ssize_t result =
            syscall(SYS_write, inherited, at ? (void*)1 : (void*)"0\n", at == 2 ? 0 : 2);
        error = result < 0 ? errno : 0;
        printf("IO_CAP_WRITE administrator=%d uid=%u kind=%u result=%ld error=%d\n", administrator,
               (unsigned)getuid(), at, (long)result, error);
    }
    _exit(0);
}

static int scoped_open(const char* scope, const char* name, int flags) {
    char path[256];
    snprintf(path, sizeof(path), "/proc/sys/net/ipv6/conf/%s/%s", scope, name);
    return open(path, flags | O_CLOEXEC);
}

static void secret_read(const char* scope) {
    int fd = scoped_open(scope, "stable_secret", O_RDONLY);
    must(fd >= 0);
    struct stat metadata;
    must(fstat(fd, &metadata) == 0);
    char bytes[96] = {0};
    errno = 0;
    ssize_t result = read(fd, bytes, sizeof(bytes));
    int error = result < 0 ? errno : 0;
    printf("IO_SECRET_READ scope=%s mode=%o result=%ld error=%d bytes=", scope,
           (unsigned)metadata.st_mode & 0777, (long)result, error);
    for (ssize_t at = 0; at < result; at++)
        printf("%02x", (unsigned char)bytes[at]);
    puts("");
    must(close(fd) == 0);
}

static void secret_write(const char* scope, const char* value) {
    int fd = scoped_open(scope, "stable_secret", O_WRONLY);
    must(fd >= 0);
    errno = 0;
    ssize_t result = write(fd, value, strlen(value));
    int error = result < 0 ? errno : 0;
    printf("IO_SECRET_WRITE scope=%s result=%ld error=%d offset=%ld\n", scope, (long)result, error,
           (long)lseek(fd, 0, SEEK_CUR));
    must(close(fd) == 0);
}

static void state(const char* phase) {
    const char* scopes[] = {"all", "default", "eth0", "eth1", "lo"};
    for (unsigned at = 0; at < 5; at++) {
        int fd = scoped_open(scopes[at], "addr_gen_mode", O_RDONLY);
        char bytes[16] = {0};
        must(fd >= 0 && read(fd, bytes, sizeof(bytes) - 1) > 0 && close(fd) == 0);
        printf("IO_SECRET_STATE phase=%s scope=%s mode=%d\n", phase, scopes[at], atoi(bytes));
    }
    struct ifaddrs* addresses = NULL;
    must(getifaddrs(&addresses) == 0);
    for (struct ifaddrs* item = addresses; item; item = item->ifa_next) {
        if (!item->ifa_addr || item->ifa_addr->sa_family != AF_INET6)
            continue;
        char address[64];
        struct sockaddr_in6* value = (struct sockaddr_in6*)item->ifa_addr;
        must(inet_ntop(AF_INET6, &value->sin6_addr, address, sizeof(address)) != NULL);
        printf("IO_SECRET_ADDRESS phase=%s name=%s address=%s\n", phase, item->ifa_name, address);
    }
    freeifaddrs(addresses);
}

static void link_change(const char* name, int up) {
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    struct ifreq request = {0};
    snprintf(request.ifr_name, sizeof(request.ifr_name), "%s", name);
    must(fd >= 0 && ioctl(fd, SIOCGIFFLAGS, &request) == 0);
    if (up)
        request.ifr_flags |= IFF_UP;
    else
        request.ifr_flags &= ~IFF_UP;
    must(ioctl(fd, SIOCSIFFLAGS, &request) == 0 && close(fd) == 0 && usleep(100000) == 0);
}

static void extra(void) {
    write_value("vector-reset", "addr_gen_mode", "0\n");
    int fd = open_setting("addr_gen_mode", O_RDWR);
    must(fd >= 0);
    unsigned char bytes[2] = {0};
    struct iovec read_vectors[2] = {{bytes, 1}, {bytes + 1, 1}};
    errno = 0;
    ssize_t result = readv(fd, read_vectors, 2);
    printf("IO_READ_VECTOR result=%ld error=%d offset=%ld bytes=%02x%02x\n", (long)result,
           result < 0 ? errno : 0, (long)lseek(fd, 0, SEEK_CUR), bytes[0], bytes[1]);
    must(lseek(fd, 0, SEEK_SET) == 0);
    struct iovec invalid[2] = {{"1", 1}, {"junk\n", 5}};
    vector_result("invalid-combined", fd, invalid, 2);
    struct iovec fault[2] = {{"1", 1}, {(void*)1, 1}};
    vector_result("fault-combined", fd, fault, 2);
    long page = sysconf(_SC_PAGESIZE);
    must(page > 0);
    char* mapping =
        mmap(NULL, (size_t)page * 2, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    must(mapping != MAP_FAILED && mprotect(mapping + page, (size_t)page, PROT_NONE) == 0);
    mapping[page - 1] = '1';
    struct iovec boundary = {mapping + page - 1, 2};
    vector_result("fault-page", fd, &boundary, 1);
    must(munmap(mapping, (size_t)page * 2) == 0);
    struct iovec good[2] = {{"1", 1}, {"\n", 1}};
    vector_result("valid-combined", fd, good, 2);
    must(lseek(fd, 0, SEEK_SET) == 0 && write(fd, "0\n", 2) == 2);
    for (int administrator = 0; administrator < 2; administrator++) {
        pid_t child = fork();
        must(child >= 0);
        if (!child)
            capability_child(fd, administrator);
        int status;
        must(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    }
    must(close(fd) == 0);
    fd = open_setting("accept_ra", O_WRONLY);
    must(fd >= 0);
    errno = 0;
    result = write(fd, "1 2\n", 4);
    printf("IO_SIGNED_OFFSET result=%ld error=%d offset=%ld value=%d\n", (long)result,
           result < 0 ? errno : 0, (long)lseek(fd, 0, SEEK_CUR), current("accept_ra"));
    must(close(fd) == 0);
    secret_read("all");
    secret_read("default");
    secret_read("eth0");
    write_value("secret-no-generation", "addr_gen_mode", "1\n");
    fd = scoped_open("eth1", "addr_gen_mode", O_WRONLY);
    must(fd >= 0 && write(fd, "1\n", 2) == 2 && close(fd) == 0);
    link_change("eth0", 1);
    link_change("eth1", 1);
    state("before-secret");
    secret_write("eth0", "2001:db8::1234\n");
    secret_read("eth0");
    state("per-link-secret");
    link_change("eth0", 0);
    link_change("eth0", 1);
    state("per-link-cycle");
    secret_write("default", "2001:db8::5678\n");
    secret_read("default");
    state("default-secret");
    secret_write("eth0", "bad\n");
    secret_read("eth0");
    secret_write("all", "2001:db8::9\n");
    state("after-errors");
    puts("SYSCTL_FRONTEND_COMPLETE");
}

int main(void) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    must(getuid() == 0);
    int fd = open_setting("addr_gen_mode", O_RDWR);
    must(fd >= 0);
    read_part("first-byte", fd, 1);
    read_part("second-byte", fd, 1);
    must(lseek(fd, 0, SEEK_SET) == 0);
    read_part("rewound", fd, 64);
    must(lseek(fd, 0, SEEK_SET) == 0);
    errno = 0;
    ssize_t result = write(fd, "1\n", 2);
    int error = result < 0 ? errno : 0;
    printf("IO_OFFSET label=first-write result=%ld error=%d offset=%ld value=%d\n", (long)result,
           error, (long)lseek(fd, 0, SEEK_CUR), current("addr_gen_mode"));
    result = write(fd, "0\n", 2);
    error = result < 0 ? errno : 0;
    printf("IO_OFFSET label=second-write result=%ld error=%d offset=%ld value=%d\n", (long)result,
           error, (long)lseek(fd, 0, SEEK_CUR), current("addr_gen_mode"));
    must(lseek(fd, 0, SEEK_SET) == 0);
    must(write(fd, "0\n", 2) == 2);
    must(lseek(fd, 0, SEEK_SET) == 0);
    pid_t child = fork();
    must(child >= 0);
    if (!child) {
        must(setuid(65534) == 0);
        errno = 0;
        result = write(fd, "1\n", 2);
        error = result < 0 ? errno : 0;
        printf("IO_INHERITED uid=%u result=%ld error=%d value=%d\n", (unsigned)getuid(),
               (long)result, error, current("addr_gen_mode"));
        _exit(0);
    }
    int status;
    must(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    must(close(fd) == 0);
    fd = open_setting("addr_gen_mode", O_WRONLY | O_TRUNC);
    int opened_error = fd < 0 ? errno : 0;
    printf("IO_TRUNC label=open opened=%d error=%d value=%d\n", fd >= 0, opened_error,
           current("addr_gen_mode"));
    must(fd >= 0);
    errno = 0;
    int truncated = ftruncate(fd, 0);
    error = truncated < 0 ? errno : 0;
    printf("IO_TRUNC label=ftruncate result=%d error=%d value=%d\n", truncated, error,
           current("addr_gen_mode"));
    must(close(fd) == 0);
    const char* values[] = {" 1 \n", "+0\n", "0x1\n", "00\n",        "1junk\n",
                            "1 0\n", "",     "\n",    "2147483648\n"};
    const char* labels[] = {"whitespace", "plus",  "hex",     "octal",   "suffix",
                            "two-values", "empty", "newline", "overflow"};
    for (unsigned at = 0; at < sizeof(values) / sizeof(values[0]); at++)
        write_value(labels[at], "addr_gen_mode", values[at]);
    for (unsigned key = 0; key < 6; key++) {
        const char* names[] = {"accept_ra",    "autoconf",      "disable_ipv6",
                               "enhanced_dad", "dad_transmits", "router_solicitations"};
        write_value("negative", names[key], "-1\n");
        write_value("two", names[key], "2\n");
        write_value("restore", names[key], key == 2 ? "0\n" : "1\n");
    }
    printf("SYSCTL_IO_COMPLETE counted=%u\n", count);
    extra();
    return 0;
}
