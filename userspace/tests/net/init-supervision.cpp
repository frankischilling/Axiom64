// SPDX-License-Identifier: GPL-3.0-or-later
#include "net/config/profile.hpp"
#include "net/config/routing.hpp"
#include "net/dhcp/transport.hpp"
#include "net/manager/ownership.hpp"
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

namespace {
constexpr const char* profile_path = "/etc/network/eth0.conf";
constexpr const char* lock_path = "/run/network-manager/manager.lock";

struct State {
    uint64_t device, inode;
    pid_t first;
};

void check(bool value, const char* reason) {
    if (!value) {
        fprintf(stderr, "INIT_OBSERVER_FAIL %s errno=%d\n", reason, errno);
        exit(1);
    }
}

uint64_t milliseconds() {
    timespec now;
    check(clock_gettime(CLOCK_MONOTONIC, &now) == 0, "monotonic clock");
    return uint64_t(now.tv_sec) * 1000 + uint64_t(now.tv_nsec) / 1000000;
}

void pause_ms(unsigned value) {
    timespec interval{value / 1000, long(value % 1000) * 1000000};
    while (nanosleep(&interval, &interval) < 0)
        check(errno == EINTR, "observer wait");
}

size_t read_file(const char* path, void* output, size_t capacity) {
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    check(fd >= 0, "open observed file");
    size_t used = 0;
    for (;;) {
        char extra;
        ssize_t count = read(fd, used == capacity ? &extra : static_cast<char*>(output) + used,
                             used == capacity ? 1 : capacity - used);
        if (count < 0 && errno == EINTR)
            continue;
        check(count >= 0 && size_t(count) <= capacity - used, "bounded file read");
        if (!count)
            break;
        used += size_t(count);
    }
    check(close(fd) == 0, "close observed file");
    return used;
}

void save(const char* path, const void* data, size_t length) {
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    check(fd >= 0, "create volatile observer record");
    size_t used = 0;
    while (used < length) {
        ssize_t count = write(fd, static_cast<const char*>(data) + used, length - used);
        if (count < 0 && errno == EINTR)
            continue;
        check(count > 0, "write observer record");
        used += size_t(count);
    }
    check(fsync(fd) == 0 && close(fd) == 0, "sync and close observer record");
}

struct stat metadata(const char* path, unsigned mode, bool directory = false) {
    struct stat value;
    check(lstat(path, &value) == 0 &&
              (directory ? S_ISDIR(value.st_mode) : S_ISREG(value.st_mode)) &&
              (value.st_mode & 07777) == mode && value.st_uid == geteuid() &&
              value.st_gid == getegid() && (directory || value.st_nlink == 1),
          "private inode type/mode/owner/link count");
    return value;
}

bool absent(const char* path) {
    struct stat information;
    if (lstat(path, &information) == 0)
        return false;
    check(errno == ENOENT, "checked missing pathname");
    return true;
}

State state() {
    State value{};
    check(read_file("/run/init-supervision-state", &value, sizeof(value)) == sizeof(value),
          "read first process and permanent lock identity");
    return value;
}

void ownership(bool held = true) {
    metadata("/run/network-manager", 0700, true);
    auto actual = metadata(lock_path, 0600);
    State saved = state();
    check(uint64_t(actual.st_dev) == saved.device && uint64_t(actual.st_ino) == saved.inode,
          "restart retains the same permanent singleton inode");
    ax::net::Ownership contender;
    int error = contender.open("/run/network-manager");
    check(error == EAGAIN || error == EWOULDBLOCK || (!held && error == 0),
          "installed process owns the checked singleton");
    check(contender.close() == 0, "close independent singleton contender");
}

void profile() {
    metadata("/etc/network", 0700, true);
    metadata(profile_path, 0600);
    ax::net::Store saved("/etc/network");
    ax::net::Profile selected;
    check(saved.read_profile("eth0", selected) == 0 && selected.method == ax::net::Method::dhcp &&
              !strcmp(selected.hostname, "normal-init"),
          "production Store reads the unchanged saved profile");
    char before[512], after[512];
    size_t first = read_file("/run/init-supervision-profile", before, sizeof(before));
    size_t second = read_file(profile_path, after, sizeof(after));
    check(first == second && !memcmp(before, after, first), "saved profile bytes unchanged");
}

void hints(unsigned mask, unsigned interfaces) {
    ax::net::Store saved("/etc/network");
    for (unsigned lane = 0; lane < interfaces; lane++) {
        ax::dhcp::Interface information;
        check(ax::dhcp::query_interface(lane + 1, information) == 0,
              "independent Ethernet interface query");
        const uint8_t mac[]{0x52, 0x54, 0, 0x12, 0x34, uint8_t(0x10 + lane)};
        check(!memcmp(information.identity.mac, mac, sizeof(mac)), "actual adapter MAC identity");
        uint32_t address = 0;
        int error = saved.read_hint(information.name, information.identity, address);
        if (mask & (1U << lane)) {
            check(error == 0 && address == (0x0a170128U + (lane << 8)),
                  "private hint retains only a matching saved address");
            char path[100];
            snprintf(path, sizeof(path), "/etc/network/%s.lease", information.name);
            metadata(path, 0600);
        } else
            check(error == ENOENT, "unconfigured or released adapter has no hint");
    }
}

bool addresses(unsigned mask, unsigned interfaces, bool changed) {
    for (unsigned lane = 0; lane < interfaces; lane++) {
        char name[16];
        snprintf(name, sizeof(name), "eth%u", lane);
        uint32_t address = 0, netmask = 0;
        check(ax::dhcp::query_address(name, address, netmask) == 0, "independent address query");
        bool healthy = mask & (1U << lane);
        if (address != (healthy ? 0x0a170128U + (lane << 8) : 0) ||
            (healthy && netmask != (changed ? 0xffffff80U : 0xffffff00U)))
            return false;
    }
    return true;
}

void configuration(unsigned mask, unsigned interfaces, bool changed) {
    check(addresses(mask, interfaces, changed), "actual complete address tuples");
    ax::net::Routing observer;
    check(observer.open() == 0, "independent route socket");
    ax::net::Route rows[64];
    size_t count = 0;
    check(observer.list(rows, 64, count) == 0, "complete independent route dump");
    unsigned seen = 0;
    for (size_t i = 0; i < count; i++) {
        const auto& row = rows[i];
        if (row.protocol != 16)
            continue;
        check(row.index >= 1 && row.index <= interfaces, "route belongs to an actual adapter");
        unsigned lane = row.index - 1;
        check((mask & (1U << lane)) && !(seen & (1U << lane)) && row.destination == 0 &&
                  row.mask == 0 && row.gateway == 0x0a170101U + (lane << 8) + unsigned(changed) &&
                  row.metric == 101 + lane && row.scope == 0,
              "exact owned default route uses the accepted ACK gateway");
        seen |= 1U << lane;
    }
    check(seen == mask, "all and only accepted adapters own routes");
    char output[2048]{};
    size_t length = read_file("/run/network-resolver/resolv.conf", output, sizeof(output) - 1);
    output[length] = 0;
    check(!strstr(output, ".99\n"), "OFFER resolver input is never installed");
    for (unsigned lane = 0; lane < 2; lane++) {
        char wanted[64], stale[64];
        snprintf(wanted, sizeof(wanted), "nameserver 10.23.%u.%u\n", lane + 1, changed ? 54 : 53);
        snprintf(stale, sizeof(stale), "nameserver 10.23.%u.%u\n", lane + 1, changed ? 53 : 54);
        check(bool(strstr(output, wanted)) == bool(mask & (1U << lane)) && !strstr(output, stale),
              "merged resolver contains only each accepted fresh ACK contribution");
    }
    char link[256];
    constexpr const char* target = "/run/network-resolver/resolv.conf";
    ssize_t size = readlink("/etc/resolv.conf", link, sizeof(link));
    check(size == ssize_t(strlen(target)) && !memcmp(link, target, size),
          "normal resolver target points at the real volatile output");
    for (unsigned lane = 0; lane < interfaces; lane++) {
        char path[100];
        snprintf(path, sizeof(path), "/run/network-manager/eth%u.owned", lane);
        check(absent(path) == !(mask & (1U << lane)), "checked ownership journal lifetime");
        if (mask & (1U << lane))
            metadata(path, 0600);
    }
}

void reaped(pid_t process) {
    uint64_t until = milliseconds() + 15000;
    for (;;) {
        if (kill(process, 0) < 0) {
            check(errno == ESRCH, "exited PID is gone after normal PID1 reaps it");
            return;
        }
        check(milliseconds() < until, "normal init reaps the actual signalled child");
        pause_ms(20);
    }
}
} // namespace

int main(int argc, char** argv) {
    setvbuf(stdout, nullptr, _IOLBF, 0);
    check(argc == 5, "phase, actual PID, healthy mask and interface count required");
    const char* phase = argv[1];
    pid_t process = pid_t(atoi(argv[2]));
    unsigned mask = unsigned(atoi(argv[3])), interfaces = unsigned(atoi(argv[4]));
    check(process > 1 && interfaces <= 2 && mask < 4 && !(mask >> interfaces),
          "observer arguments");
    check(kill(1, 0) == 0 && getpid() != 1 && getppid() != 1, "observer is a serial-shell process");
    if (!strcmp(phase, "desktop-before") || !strcmp(phase, "desktop-after")) {
        char path[100];
        snprintf(path, sizeof(path), "/tmp/init-keyboard-%s", phase + 8);
        struct stat information;
        check(lstat(path, &information) == 0 && S_ISREG(information.st_mode),
              "physical keyboard reaches the normal xterm Bash session");
    } else if (!strcmp(phase, "initial")) {
        check(kill(process, 0) == 0, "first installed manager is alive");
        uint64_t until = milliseconds() + 60000;
        while (!addresses(mask, interfaces, false)) {
            check(milliseconds() < until,
                  "healthy adapters acquire independently of missing peers");
            pause_ms(20);
        }
        configuration(mask, interfaces, false);
        hints(mask, interfaces);
        ax::net::Store saved("/etc/network");
        ax::net::Profile selected;
        strcpy(selected.hostname, "normal-init");
        metadata("/etc/network", 0700, true);
        check(saved.write_profile("eth0", selected) == 0,
              "save profile through the production Store");
        char bytes[512];
        size_t length = read_file(profile_path, bytes, sizeof(bytes));
        save("/run/init-supervision-profile", bytes, length);
        auto lock = metadata(lock_path, 0600);
        State record{uint64_t(lock.st_dev), uint64_t(lock.st_ino), process};
        save("/run/init-supervision-state", &record, sizeof(record));
        save("/run/network-manager/init-observer-marker", "volatile\n", 9);
        ownership();
        profile();
    } else if (!strcmp(phase, "kill")) {
        check(process == state().first, "signal the observed first manager PID");
        ownership();
        profile();
        hints(mask, interfaces);
        configuration(mask, interfaces, false);
        printf("INIT_OBSERVER_SIGNAL pid=%d signal=%d monotonic_ms=%llu\n", process, SIGKILL,
               (unsigned long long)milliseconds());
        check(kill(process, SIGKILL) == 0,
              "kill the installed manager without a replacement supervisor");
    } else if (!strcmp(phase, "revalidating") || !strcmp(phase, "recovered")) {
        check(process != state().first, "PID1 chooses a new actual process");
        reaped(state().first);
        check(kill(process, 0) == 0, "replacement installed manager is alive");
        ownership();
        profile();
        hints(mask, interfaces);
        configuration(!strcmp(phase, "recovered") ? mask : 0, interfaces, true);
    } else if (!strcmp(phase, "stop")) {
        check(process != state().first, "stop the actual replacement process");
        ownership();
        printf("INIT_OBSERVER_SIGNAL pid=%d signal=%d monotonic_ms=%llu\n", process, SIGTERM,
               (unsigned long long)milliseconds());
        check(kill(process, SIGTERM) == 0, "signal the installed replacement manager");
        reaped(process);
        check(addresses(0, interfaces, false), "signal withdraws every owned address");
        configuration(0, interfaces, true);
        hints(0, interfaces);
        profile();
        ownership(false);
    } else
        check(false, "unknown observer phase");
    printf("INIT_OBSERVER_PASS phase=%s pid=%d monotonic_ms=%llu\n", phase, process,
           (unsigned long long)milliseconds());
    return 0;
}
