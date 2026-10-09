// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "net/config/profile.hpp"
#include "net/config/routing.hpp"
#include "net/dhcp/transport.hpp"
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static void check(bool value, const char* reason) {
    if (!value) {
        fprintf(stderr, "MANAGER_TEST_FAIL %s errno=%d\n", reason, errno);
        exit(1);
    }
}

static uint64_t milliseconds() {
    timespec now;
    check(clock_gettime(CLOCK_MONOTONIC, &now) == 0, "observer monotonic clock");
    return uint64_t(now.tv_sec) * 1000 + uint64_t(now.tv_nsec) / 1000000;
}

static void pause_ms(unsigned value) {
    timespec interval{value / 1000, long(value % 1000) * 1000000};
    while (nanosleep(&interval, &interval) < 0)
        check(errno == EINTR, "observer wait");
}

static size_t text(const char* path, char* output, size_t capacity, bool optional = false) {
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NONBLOCK | O_NOFOLLOW);
    if (optional && fd < 0 && errno == ENOENT) {
        output[0] = 0;
        return 0;
    }
    check(fd >= 0, "observer opens file");
    size_t used = 0;
    for (;;) {
        ssize_t count = read(fd, output + used, capacity - used - 1);
        if (count < 0 && errno == EINTR)
            continue;
        check(count >= 0, "observer reads file");
        if (!count)
            break;
        used += size_t(count);
        check(used + 1 < capacity, "observer file bound");
    }
    output[used] = 0;
    check(close(fd) == 0, "observer closes file");
    return used;
}

static bool fault_scenario(const char* scenario) {
    return !strcmp(scenario, "hint-sync") || !strcmp(scenario, "resolver") ||
           !strcmp(scenario, "hint-remove") || !strcmp(scenario, "close");
}

struct Fixture {
    char runtime[256], saved[256], resolver[256], target[256], log[300];
    ax::dhcp::Interface interfaces[2];
    const char* binary;
    const char* scenario;
    pid_t process = -1;
    unsigned serial = 0, primary = 0;
    bool manual_installed[2]{};

    Fixture(const char* executable, const char* selected, const char* root)
        : binary(executable), scenario(selected) {
        const char* linkage = strstr(binary, "dynamic") ? "dynamic" : "static";
        bool reboot = !strcmp(scenario, "persist-reboot");
        const char* key = !strncmp(scenario, "persist-", 8) ? "persistent" : scenario;
        char directory[220];
        snprintf(directory, sizeof(directory), "%s/manager-%s-%s", root, key, linkage);
        if (reboot) {
            struct stat before;
            check(lstat(directory, &before) == 0 && S_ISDIR(before.st_mode) &&
                      (before.st_mode & 07777) == 0700 && before.st_uid == geteuid(),
                  "fresh boot retains the private persistent fixture");
            serial = 2;
        } else
            check(mkdir(directory, 0700) == 0, "private observer fixture");
        snprintf(saved, sizeof(saved), "%s/saved", directory);
        snprintf(runtime, sizeof(runtime), "/run/manager-%s-%s", key, linkage);
        snprintf(resolver, sizeof(resolver), "/run/manager-resolver-%s-%s", key, linkage);
        snprintf(target, sizeof(target), "/etc/manager-%s-%s.conf", key, linkage);
        snprintf(log, sizeof(log), "%s/child-0.log", directory);
        for (unsigned i = 0; i < 2; i++)
            check(ax::dhcp::query_interface(i + 1, interfaces[i]) == 0,
                  "observer Ethernet identity");
    }

    pid_t start(bool competing = false, bool inject = true) {
        char destination[340];
        snprintf(destination, sizeof(destination), "%s.%u", log, ++serial);
        int output = open(destination, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
        check(output >= 0, "child evidence file");
        pid_t child = fork();
        check(child >= 0, "actual manager fork");
        if (!child) {
            check(dup2(output, 1) == 1 && dup2(output, 2) == 2 && close(output) == 0,
                  "manager evidence descriptors");
            char fault_binary[300];
            const char* executable = binary;
            check(unsetenv("MANAGER_FAULT") == 0, "clear inherited fault selection");
            if (inject && fault_scenario(scenario)) {
                check(setenv("MANAGER_FAULT", scenario, 1) == 0, "select test-only failure");
                snprintf(fault_binary, sizeof(fault_binary), "%s-faults", binary);
                executable = fault_binary;
            }
            execl(executable, executable, "--runtime", runtime, "--saved", saved,
                  "--resolver-runtime", resolver, "--resolver-target", target,
                  static_cast<char*>(nullptr));
            _exit(127);
        }
        check(close(output) == 0, "observer closes child evidence descriptor");
        if (!competing) {
            process = child;
            primary = serial;
        }
        return child;
    }

    bool marker(const char* value, unsigned evidence = 0) const {
        char path[340], bytes[65536];
        snprintf(path, sizeof(path), "%s.%u", log, evidence ? evidence : primary);
        text(path, bytes, sizeof(bytes));
        return strstr(bytes, value);
    }

    void evidence(unsigned number) const {
        char path[340], bytes[65536];
        snprintf(path, sizeof(path), "%s.%u", log, number);
        text(path, bytes, sizeof(bytes));
        printf("MANAGER_CHILD_EVIDENCE number=%u\n%s", number, bytes);
    }

    int wait(pid_t child, unsigned timeout = 8000) const {
        uint64_t until = milliseconds() + timeout;
        int status;
        for (;;) {
            pid_t result = waitpid(child, &status, WNOHANG);
            check(result >= 0, "actual manager waitpid");
            if (result == child)
                return status;
            check(milliseconds() < until, "bounded actual process exit");
            pause_ms(20);
        }
    }

    uint32_t address(unsigned lane, uint32_t* mask = nullptr) const {
        uint32_t value, netmask;
        check(ax::dhcp::query_address(interfaces[lane].name, value, netmask) == 0,
              "independent complete address query");
        if (mask)
            *mask = netmask;
        return value;
    }

    void routes(bool first, bool second, bool manual, bool fixed = false) const {
        ax::net::Routing observer;
        check(observer.open() == 0, "independent route observer");
        for (unsigned lane = 0; lane < 2; lane++) {
            ax::net::Route rows[64];
            size_t count = 0;
            check(observer.list(rows, 64, count, lane + 1) == 0, "independent route dump");
            unsigned owned = 0, retained = 0;
            for (size_t i = 0; i < count; i++) {
                owned +=
                    rows[i].protocol == (fixed && !lane ? 4 : 16) && rows[i].metric == 101 + lane;
                retained += rows[i].protocol == 4 && rows[i].destination == 0xc6336400 &&
                            rows[i].mask == 0xffffff00 && rows[i].metric == 901 + lane;
            }
            check(owned == unsigned(lane ? second : first) &&
                      retained == unsigned(manual && manual_installed[lane]),
                  "owned default routes and manual route preservation");
        }
    }

    void manual_routes(bool remove = false) {
        ax::net::Routing observer;
        check(observer.open() == 0, "manual route writer");
        for (unsigned index = 1; index <= 2; index++) {
            if (remove ? !manual_installed[index - 1] : !address(index - 1))
                continue;
            ax::net::Route route{0xc6336400, 0xffffff00, 0, 900 + index, index, 4, 253};
            check(observer.change(route, remove) == 0, "manual route fixture");
            manual_installed[index - 1] = !remove;
        }
    }

    void stop(bool failed = false) {
        check(kill(process, SIGTERM) == 0, "signal actual manager");
        int status = wait(process);
        evidence(primary);
        check(WIFEXITED(status) && WEXITSTATUS(status) == (failed ? 1 : 0),
              "checked manager exit reports complete or failed teardown");
        if (failed) {
            char expected[100];
            snprintf(expected, sizeof(expected), "MANAGER_FAULT_INJECT operation=%s errno=5",
                     scenario);
            check(marker(expected) && marker("NETWORK_MANAGER_EXIT status=1"),
                  "real selected failure occurs before reported error exit");
        }
        process = -1;
    }

    void clean(bool retained_hint = false) const {
        char path[300], bytes[1024];
        for (unsigned lane = 0; lane < 2; lane++) {
            snprintf(path, sizeof(path), "%s/%.15s.owned", runtime, interfaces[lane].name);
            check(access(path, F_OK) < 0 && errno == ENOENT, "checked ownership journal removal");
            snprintf(path, sizeof(path), "%s/%.15s.lease", saved, interfaces[lane].name);
            if (retained_hint && !lane) {
                ax::net::Store store(saved);
                uint32_t value = 0;
                check(store.read_hint(interfaces[lane].name, interfaces[lane].identity, value) ==
                              0 &&
                          value == 0x0a170128,
                      "failed hint removal retains the complete private recoverable hint");
            } else
                check(access(path, F_OK) < 0 && errno == ENOENT,
                      "release removes saved address hint");
        }
        snprintf(path, sizeof(path), "%s/resolv.conf", resolver);
        text(path, bytes, sizeof(bytes));
        check(!strstr(bytes, "nameserver "), "signal withdraws all owned resolver contributions");
    }
};
