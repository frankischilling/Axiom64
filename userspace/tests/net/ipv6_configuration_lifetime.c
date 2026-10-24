// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

static const char* properties[] = {
    "disable_ipv6",  "addr_gen_mode", "max_addresses",        "stable_secret", "autoconf",
    "dad_transmits", "enhanced_dad",  "router_solicitations", "accept_ra"};
static int control;

static void require(int condition, const char* operation) {
    if (!condition) {
        printf("LIFETIME_IO_FATAL operation=%s errno=%d\n", operation, errno);
        exit(1);
    }
}

static void path(char output[160], const char* scope, const char* property) {
    snprintf(output, 160, "/proc/sys/net/ipv6/conf/%s/%s", scope, property);
}

static void scalar(const char* scope, const char* property, const char* value) {
    char name[160];
    path(name, scope, property);
    int fd = open(name, O_WRONLY | O_CLOEXEC);
    require(fd >= 0, "open configuration setup");
    size_t length = strlen(value);
    require(write(fd, value, length) == (ssize_t)length, "write configuration setup");
    require(!close(fd), "close configuration setup");
}

static void link_change(unsigned lane, int mtu, int up) {
    struct ifreq request = {0};
    snprintf(request.ifr_name, sizeof(request.ifr_name), "eth%u", lane);
    if (mtu) {
        request.ifr_mtu = mtu;
        require(!ioctl(control, SIOCSIFMTU, &request), "change real interface MTU");
    } else {
        require(!ioctl(control, SIOCGIFFLAGS, &request), "read real interface flags");
        request.ifr_flags = up ? request.ifr_flags | IFF_UP : request.ifr_flags & ~IFF_UP;
        require(!ioctl(control, SIOCSIFFLAGS, &request), "change real administrative state");
    }
}

static void setup(void) {
    scalar("all", "disable_ipv6", "1\n");
    scalar("default", "stable_secret", "fd00::100\n");
    scalar("default", "addr_gen_mode", "1\n");
    scalar("default", "max_addresses", "7\n");
    scalar("default", "autoconf", "0\n");
    scalar("default", "dad_transmits", "3\n");
    scalar("default", "enhanced_dad", "0\n");
    scalar("default", "router_solicitations", "0\n");
    scalar("default", "accept_ra", "0\n");
    for (unsigned lane = 0; lane < 2; lane++) {
        char scope[16], secret[32];
        snprintf(scope, sizeof(scope), "eth%u", lane);
        snprintf(secret, sizeof(secret), "fd00::%u\n", 10 + lane);
        link_change(lane, 1500, 0);
        link_change(lane, 0, 1);
        scalar(scope, "stable_secret", secret);
        scalar(scope, "addr_gen_mode", "1\n");
        scalar(scope, "max_addresses", "3\n");
        scalar(scope, "autoconf", "1\n");
        scalar(scope, "dad_transmits", "1\n");
        scalar(scope, "enhanced_dad", "1\n");
        scalar(scope, "router_solicitations", "0\n");
        scalar(scope, "accept_ra", "1\n");
        scalar(scope, "disable_ipv6", "0\n");
    }
}

static void bytes(const unsigned char* data, ssize_t length) {
    for (ssize_t at = 0; at < length; at++)
        printf("%02x", data[at]);
}

static void read_value(int fd) {
    unsigned char buffer[128];
    memset(buffer, 0x5a, sizeof(buffer));
    errno = 0;
    ssize_t count = read(fd, buffer, sizeof(buffer));
    int error = errno;
    printf(" read=%zd errno=%d bytes=", count, error);
    bytes(buffer, count > 0 ? count : 0);
    printf(" tail=%02x\n", buffer[count > 0 && count < (ssize_t)sizeof(buffer) ? count : 0]);
}

static void observation(unsigned lane, unsigned action, unsigned stage, int descriptors[9],
                        int directory, ino_t original_inode) {
    char scope[16], name[160];
    snprintf(scope, sizeof(scope), "eth%u", lane);
    for (unsigned observed = 0; observed < 2; observed++) {
        char selected[16];
        snprintf(selected, sizeof(selected), "eth%u", observed);
        for (unsigned at = 0; at < 9; at++) {
            path(name, selected, properties[at]);
            errno = 0;
            int fd = open(name, O_RDONLY | O_CLOEXEC);
            int error = errno;
            printf("LIFETIME_IO lane=%u action=%u stage=%u scope=%u property=%s open=%d errno=%d",
                   lane, action, stage, observed, properties[at], fd >= 0, error);
            if (fd >= 0) {
                read_value(fd);
                close(fd);
            } else
                putchar('\n');
        }
    }
    for (unsigned at = 0; at < 9; at++) {
        int fd = descriptors[at];
        errno = 0;
        off_t position = lseek(fd, 0, SEEK_SET);
        int error = errno;
        printf("LIFETIME_IO lane=%u action=%u stage=%u retained=%s seek=%lld errno=%d", lane,
               action, stage, properties[at], (long long)position, error);
        read_value(fd);
        errno = 0;
        ssize_t empty_read = read(fd, NULL, 0);
        error = errno;
        printf("LIFETIME_IO lane=%u action=%u stage=%u retained=%s empty_read=%zd errno=%d\n", lane,
               action, stage, properties[at], empty_read, error);
        require(lseek(fd, 0, SEEK_SET) == 0, "rewind retained configuration description");
        errno = 0;
        ssize_t written = write(fd, "!\n", 2);
        error = errno;
        printf("LIFETIME_IO lane=%u action=%u stage=%u retained=%s invalid_write=%zd errno=%d\n",
               lane, action, stage, properties[at], written, error);
    }
    errno = 0;
    int relative = openat(directory, "max_addresses", O_RDONLY | O_CLOEXEC);
    int error = errno;
    printf("LIFETIME_IO lane=%u action=%u stage=%u retained_directory_open=%d errno=%d", lane,
           action, stage, relative >= 0, error);
    if (relative >= 0) {
        read_value(relative);
        close(relative);
    } else
        putchar('\n');
    path(name, scope, "max_addresses");
    struct stat fresh = {0}, retained = {0};
    errno = 0;
    int result = stat(name, &fresh);
    error = errno;
    errno = 0;
    int retained_result = fstat(descriptors[2], &retained);
    int retained_error = errno;
    printf("LIFETIME_IO lane=%u action=%u stage=%u path_stat=%d errno=%d same_inode=%d "
           "retained_stat=%d retained_errno=%d retained_inode=%d\n",
           lane, action, stage, result, error, !result && fresh.st_ino == original_inode,
           retained_result, retained_error, !retained_result && retained.st_ino == original_inode);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    control = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    require(control >= 0, "open interface control socket");
    for (unsigned action = 0; action < 2; action++)
        for (unsigned lane = 0; lane < 2; lane++) {
            setup();
            char scope[16], name[160];
            snprintf(scope, sizeof(scope), "eth%u", lane);
            snprintf(name, sizeof(name), "/proc/sys/net/ipv6/conf/%s", scope);
            int directory = open(name, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
            require(directory >= 0, "open configuration directory");
            int descriptors[9];
            for (unsigned at = 0; at < 9; at++) {
                path(name, scope, properties[at]);
                descriptors[at] = open(name, O_RDWR | O_CLOEXEC);
                require(descriptors[at] >= 0, "retain configuration description");
            }
            struct stat original;
            require(!fstat(descriptors[2], &original), "stat original configuration description");
            observation(lane, action, 0, descriptors, directory, original.st_ino);
            link_change(lane, action ? 1279 : 0, 0);
            observation(lane, action, 1, descriptors, directory, original.st_ino);
            link_change(lane, action ? 1500 : 0, 1);
            observation(lane, action, 2, descriptors, directory, original.st_ino);
            for (unsigned at = 0; at < 9; at++)
                close(descriptors[at]);
            close(directory);
        }
    close(control);
    puts("LIFETIME_IO_COMPLETE interfaces=2 actions=2 stages=3");
    return 0;
}
