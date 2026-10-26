// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/if_tun.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static void require(int value, const char* message) {
    if (!value) {
        fprintf(stderr, "ICMP_FIRST_ERROR_FAIL %s errno=%d\n", message, errno);
        exit(1);
    }
}

static uint64_t now(void) {
    struct timespec value;
    require(!clock_gettime(CLOCK_MONOTONIC, &value), "monotonic clock");
    return (uint64_t)value.tv_sec * 1000000000 + value.tv_nsec;
}

static uint16_t checksum(const unsigned char* bytes, unsigned size) {
    unsigned value = 0;
    for (unsigned at = 0; at < size; at += 2)
        value += ((unsigned)bytes[at] << 8) + (at + 1 < size ? bytes[at + 1] : 0);
    while (value >> 16)
        value = (value & 65535) + (value >> 16);
    return (uint16_t)~value;
}

static void put16(unsigned char* bytes, unsigned value) {
    bytes[0] = value >> 8;
    bytes[1] = value;
}

static long counter(const char* wanted) {
    FILE* file = fopen("/proc/net/snmp", "r");
    require(file != NULL, "native counters");
    char keys[8192], values[8192];
    long result = -1;
    while (fgets(keys, sizeof(keys), file) && fgets(values, sizeof(values), file)) {
        if (strncmp(keys, "Icmp:", 5))
            continue;
        char *a = NULL, *b = NULL, *key = strtok_r(keys, " \n", &a),
             *value = strtok_r(values, " \n", &b);
        while (key && value) {
            if (!strcmp(key, wanted))
                result = strtol(value, NULL, 10);
            key = strtok_r(NULL, " \n", &a);
            value = strtok_r(NULL, " \n", &b);
        }
        break;
    }
    fclose(file);
    require(result >= 0, "named native counter");
    return result;
}

static void scalar(const char* name) {
    int fd = open(name, O_WRONLY);
    require(fd >= 0, "isolated IPv6 control");
    require(write(fd, "1\n", 2) == 2, "isolated IPv6 disable");
    close(fd);
}

static int policy(const char* name) {
    char path[128];
    snprintf(path, sizeof(path), "/proc/sys/net/ipv4/%s", name);
    FILE* file = fopen(path, "r");
    int value = -1;
    require(file != NULL && fscanf(file, "%d", &value) == 1, "actual native rate policy");
    fclose(file);
    return value;
}

struct lane {
    int fd, cpu;
    unsigned index;
    unsigned char frame[60], reply[1600];
    unsigned reply_size;
    uint64_t target, before, after, received;
};

static pthread_barrier_t barrier;

static void* inject(void* argument) {
    struct lane* lane = argument;
    cpu_set_t mask;
    CPU_ZERO(&mask);
    CPU_SET(lane->cpu, &mask);
    require(!pthread_setaffinity_np(pthread_self(), sizeof(mask), &mask), "owned packet CPU");
    int code = pthread_barrier_wait(&barrier);
    require(!code || code == PTHREAD_BARRIER_SERIAL_THREAD, "ready barrier");
    code = pthread_barrier_wait(&barrier);
    require(!code || code == PTHREAD_BARRIER_SERIAL_THREAD, "start barrier");
    while (now() < lane->target) {
    }
    lane->before = now();
    require(write(lane->fd, lane->frame, sizeof(lane->frame)) == sizeof(lane->frame),
            "complete input frame");
    lane->after = now();
    return NULL;
}

static void address(int fd, const char* name, unsigned operation, const unsigned char bytes[4]) {
    struct ifreq request = {0};
    snprintf(request.ifr_name, sizeof(request.ifr_name), "%s", name);
    struct sockaddr_in* value = (struct sockaddr_in*)&request.ifr_addr;
    value->sin_family = AF_INET;
    memcpy(&value->sin_addr, bytes, 4);
    require(!ioctl(fd, operation, &request), "isolated IPv4 address");
}

static void configure(struct lane* lane, unsigned index) {
    char name[IFNAMSIZ];
    snprintf(name, sizeof(name), "eth%u", index);
    struct ifreq request = {0};
    snprintf(request.ifr_name, sizeof(request.ifr_name), "%s", name);
    request.ifr_flags = IFF_TAP | IFF_NO_PI;
    lane->fd = open("/dev/net/tun", O_RDWR | O_NONBLOCK);
    require(lane->fd >= 0, "isolated TAP");
    require(!ioctl(lane->fd, TUNSETIFF, &request), "create isolated TAP");
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    require(fd >= 0, "isolated device control");
    const unsigned char guest[6] = {0x52, 0x54, 0, 0x12, 0x34, (unsigned char)(16 + index)};
    const unsigned char peer[6] = {2, 0x41, 0x58, 0x49, 0x50, (unsigned char)index};
    const unsigned char local[4] = {10, 202, (unsigned char)(1 + index), 2};
    const unsigned char remote[4] = {10, 202, (unsigned char)(1 + index), 1};
    memset(&request, 0, sizeof(request));
    snprintf(request.ifr_name, sizeof(request.ifr_name), "%s", name);
    request.ifr_hwaddr.sa_family = ARPHRD_ETHER;
    memcpy(request.ifr_hwaddr.sa_data, guest, 6);
    require(!ioctl(fd, SIOCSIFHWADDR, &request), "isolated hardware address");
    address(fd, name, SIOCSIFADDR, local);
    address(fd, name, SIOCSIFNETMASK, (unsigned char[4]){255, 255, 255, 0});
    memset(&request, 0, sizeof(request));
    snprintf(request.ifr_name, sizeof(request.ifr_name), "%s", name);
    request.ifr_flags = IFF_UP;
    require(!ioctl(fd, SIOCSIFFLAGS, &request), "isolated interface up");
    struct arpreq neighbor = {0};
    ((struct sockaddr_in*)&neighbor.arp_pa)->sin_family = AF_INET;
    memcpy(&((struct sockaddr_in*)&neighbor.arp_pa)->sin_addr, remote, 4);
    neighbor.arp_ha.sa_family = ARPHRD_ETHER;
    memcpy(neighbor.arp_ha.sa_data, peer, 6);
    neighbor.arp_flags = ATF_COM | ATF_PERM;
    snprintf(neighbor.arp_dev, sizeof(neighbor.arp_dev), "%s", name);
    require(!ioctl(fd, SIOCSARP, &neighbor), "isolated permanent peer");
    close(fd);
    memcpy(lane->frame, guest, 6);
    memcpy(lane->frame + 6, peer, 6);
    lane->frame[12] = 8;
    unsigned char* ip = lane->frame + 14;
    ip[0] = 0x45;
    put16(ip + 2, 28);
    put16(ip + 4, 0x7c00 + index);
    ip[8] = 64;
    ip[9] = 17;
    memcpy(ip + 12, remote, 4);
    memcpy(ip + 16, local, 4);
    put16(ip + 10, checksum(ip, 20));
    put16(ip + 20, 44000 + index);
    put16(ip + 22, 44100);
    put16(ip + 24, 8);
    lane->index = index;
}

static void hex(const unsigned char* bytes, unsigned size) {
    for (unsigned at = 0; at < size; at++)
        printf("%02x", bytes[at]);
}

static int one(unsigned trial, unsigned aligned, int cpu0, int cpu1) {
    require(!unshare(CLONE_NEWNET), "private network namespace");
    scalar("/proc/sys/net/ipv6/conf/all/disable_ipv6");
    scalar("/proc/sys/net/ipv6/conf/default/disable_ipv6");
    struct lane lanes[2] = {{.cpu = cpu0}, {.cpu = cpu1}};
    configure(lanes, 0);
    configure(lanes + 1, 1);
    require(policy("icmp_msgs_per_sec") == 1000 && policy("icmp_msgs_burst") == 50 &&
                policy("icmp_ratemask") == 6168 && policy("icmp_ratelimit") == 1000,
            "unchanged original native rate policy");
    require(counter("OutMsgs") == 0 && counter("OutRateLimitGlobal") == 0,
            "fresh native error counters");
    struct timespec delay = {0, 50000000};
    require(!nanosleep(&delay, NULL), "real first-error observation preparation");
    require(!pthread_barrier_init(&barrier, NULL, 3), "packet barrier");
    pthread_t threads[2];
    for (unsigned at = 0; at < 2; at++)
        require(!pthread_create(threads + at, NULL, inject, lanes + at), "packet thread");
    (void)pthread_barrier_wait(&barrier);
    uint64_t target = now() + 2000000;
    lanes[0].target = target;
    lanes[1].target = target + (aligned ? 0 : 1000000);
    (void)pthread_barrier_wait(&barrier);
    for (unsigned at = 0; at < 2; at++)
        require(!pthread_join(threads[at], NULL), "packet thread retirement");
    unsigned received = 0;
    uint64_t began = now();
    long global = 0, out = 0;
    while (now() - began < 1000000000) {
        struct pollfd items[2] = {{.fd = lanes[0].fd, .events = POLLIN},
                                  {.fd = lanes[1].fd, .events = POLLIN}};
        require(poll(items, 2, 1) >= 0, "actual native error readiness");
        for (unsigned at = 0; at < 2; at++)
            if (items[at].revents & POLLIN) {
                unsigned char bytes[1600];
                ssize_t size = read(lanes[at].fd, bytes, sizeof(bytes));
                require(size >= 14, "complete native frame");
                if (bytes[12] != 8 || bytes[13] != 0)
                    continue;
                require(size == 70 && bytes[14] == 0x45 && bytes[23] == 1 && bytes[34] == 3 &&
                            bytes[35] == 3,
                        "actual closed-port ICMP error");
                require(!checksum(bytes + 14, 20) && !checksum(bytes + 34, 36),
                        "actual native checksums");
                require(!memcmp(bytes, lanes[at].frame + 6, 6) &&
                            !memcmp(bytes + 6, lanes[at].frame, 6),
                        "returned interface ownership");
                require(!memcmp(bytes + 42, lanes[at].frame + 14, 28) && !lanes[at].reply_size,
                        "exact original quote once");
                memcpy(lanes[at].reply, bytes, size);
                lanes[at].reply_size = size;
                lanes[at].received = now();
                received++;
            }
        global = counter("OutRateLimitGlobal");
        out = counter("OutDestUnreachs");
        if (received + global == 2 && out == received)
            break;
    }
    require(received + global == 2 && out == received && counter("OutErrors") == 0,
            "account every original native error decision");
    printf("{\"trial\":%u,\"aligned\":%s,\"gap_ns\":%u,\"received\":%u,\"rate_global\":%ld,\"out_"
           "errors\":0,\"lanes\":[",
           trial, aligned ? "true" : "false", aligned ? 0 : 1000000, received, global);
    for (unsigned at = 0; at < 2; at++) {
        if (at)
            putchar(',');
        printf("{\"cpu\":%d,\"write_before_ns\":%llu,\"write_after_ns\":%llu,\"read_ns\":%llu,"
               "\"input\":\"",
               lanes[at].cpu, (unsigned long long)lanes[at].before,
               (unsigned long long)lanes[at].after, (unsigned long long)lanes[at].received);
        hex(lanes[at].frame, 60);
        printf("\",\"reply\":\"");
        hex(lanes[at].reply, lanes[at].reply_size);
        printf("\"}");
        close(lanes[at].fd);
    }
    puts("]}");
    return global ? 2 : 0;
}

int main(int argc, char** argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    require(argc <= 2, "explicit trial count");
    unsigned trials = argc == 2 ? (unsigned)strtoul(argv[1], NULL, 10) : 256;
    require(trials && trials <= 512, "bounded fixed trials");
    cpu_set_t mask;
    require(!sched_getaffinity(0, sizeof(mask), &mask), "native CPU inventory");
    int cpus[2] = {-1, -1};
    for (int at = 0; at < CPU_SETSIZE; at++)
        if (CPU_ISSET(at, &mask)) {
            if (cpus[0] < 0)
                cpus[0] = at;
            else {
                cpus[1] = at;
                break;
            }
        }
    require(cpus[1] >= 0, "two native CPUs");
    struct utsname kernel;
    require(!uname(&kernel), "native kernel identity");
    printf("{\"diagnostic_only\":true,\"feature_acceptance\":false,\"kernel\":\"%s\",\"fixed_"
           "trials_each\":%u}\n",
           kernel.release, trials);
    unsigned drops[2] = {0};
    for (unsigned trial = 0; trial < trials; trial++)
        for (unsigned order = 0; order < 2; order++) {
            unsigned aligned = order ^ (trial & 1);
            pid_t pid = fork();
            require(pid >= 0, "owned namespace child");
            if (!pid)
                exit(one(trial, aligned, cpus[0], cpus[1]));
            int status;
            require(waitpid(pid, &status, 0) == pid && WIFEXITED(status),
                    "namespace child retirement");
            int code = WEXITSTATUS(status);
            require(code == 0 || code == 2, "actual first-error experiment completes");
            drops[aligned] += code == 2;
        }
    printf("{\"diagnostic_complete\":true,\"profiles\":%u,\"staggered_suppressed_profiles\":%u,"
           "\"aligned_suppressed_profiles\":%u,\"feature_acceptance\":false}\n",
           trials * 2, drops[0], drops[1]);
    return 0;
}
