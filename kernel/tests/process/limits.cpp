// SPDX-License-Identifier: GPL-3.0-or-later
#include "process/limits.hpp"
#include <cassert>
#include <cerrno>
#include <cstdio>
#include <initializer_list>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

using ax::ProcessLimits;
using ax::Resource;
using ax::ResourceLimit;

static unsigned observations;

static int native(unsigned resource, const ResourceLimit* replacement, ResourceLimit* previous) {
    long result = syscall(SYS_prlimit64, 0, resource, replacement, previous);
    return result < 0 ? -errno : int(result);
}

static void unprivileged_hard_limit() {
    struct {
        uint32_t version;
        int32_t pid;
    } header{0x20080522, 0};

    struct {
        uint32_t effective, permitted, inheritable;
    } data[2]{};

    assert(syscall(SYS_capget, &header, data) == 0);
    constexpr uint32_t resource = 1u << 24;
    data[0].effective &= ~resource;
    data[0].permitted &= ~resource;
    data[0].inheritable &= ~resource;
    assert(syscall(SYS_capset, &header, data) == 0);
    assert(syscall(SYS_capget, &header, data) == 0);
    assert(!(data[0].effective & resource));
}

static void compare(ProcessLimits& limits, unsigned resource, const ResourceLimit* replacement,
                    bool alias = false) {
    ResourceLimit actual{0x123456789, 0xabcdef012}, expected = actual;
    ResourceLimit native_input = replacement ? *replacement : ResourceLimit{};
    ResourceLimit model_input = native_input;
    ResourceLimit* actual_output = alias ? &native_input : &actual;
    ResourceLimit* expected_output = alias ? &model_input : &expected;
    int host = native(resource, replacement ? &native_input : nullptr, actual_output);
    int model =
        limits.exchange(resource, replacement ? &model_input : nullptr, expected_output, false);
    if (host != model || actual_output->soft != expected_output->soft ||
        actual_output->hard != expected_output->hard) {
        std::fprintf(stderr, "PROCESS_LIMIT_DIFFERENCE resource=%u host=%d model=%d\n", resource,
                     host, model);
        _exit(1);
    }
    if (resource < unsigned(Resource::count)) {
        assert(native(resource, nullptr, &actual) == 0);
        assert(limits.exchange(resource, nullptr, &expected, false) == 0);
        assert(actual.soft == expected.soft && actual.hard == expected.hard);
    }
    observations++;
}

static void sequence(Resource resource) {
    unprivileged_hard_limit();
    unsigned number = unsigned(resource);
    uint64_t lower = resource == Resource::open_files ? 16 : 4096;
    ResourceLimit baseline{lower, 2 * lower};
    ProcessLimits limits;
    // Linux host defaults can differ. Install the same owned-child policy first.
    assert(native(number, &baseline, nullptr) == 0);
    assert(limits.exchange(number, &baseline, nullptr, false) == 0);
    compare(limits, number, nullptr);
    for (ResourceLimit replacement : {ResourceLimit{0, 2 * lower},
                                      {lower, 2 * lower},
                                      {2 * lower, 2 * lower},
                                      {2 * lower + 1, 2 * lower},
                                      {0, lower},
                                      {lower, 2 * lower},
                                      {2 * lower, lower},
                                      {lower, lower},
                                      {ax::resource_infinity, lower},
                                      {ax::resource_infinity, ax::resource_infinity}})
        compare(limits, number, &replacement);
    ResourceLimit aliased{lower / 2, lower};
    compare(limits, number, &aliased, true);
    compare(limits, number, nullptr);
    assert(observations == 13);
}

static void invalid_and_infinite() {
    unprivileged_hard_limit();
    ProcessLimits limits;
    for (unsigned resource : {16u, 17u, UINT32_MAX})
        compare(limits, resource, nullptr);
    unsigned resource = unsigned(Resource::file_size);
    ResourceLimit original{};
    assert(native(resource, nullptr, &original) == 0);
    assert(original.soft == ax::resource_infinity && original.hard == ax::resource_infinity);
    compare(limits, resource, nullptr);
    ResourceLimit large{(UINT64_C(1) << 63) + 19, ax::resource_infinity};
    compare(limits, resource, &large);
    large = {ax::resource_infinity, ax::resource_infinity};
    compare(limits, resource, &large);
    assert(observations == 6);
}

static void isolated(void (*run)()) {
    pid_t child = fork();
    assert(child >= 0);
    if (!child) {
        run();
        _exit(0);
    }
    int status = 0;
    assert(waitpid(child, &status, 0) == child);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

int main() {
    isolated([] { sequence(Resource::file_size); });
    isolated([] { sequence(Resource::open_files); });
    isolated(invalid_and_infinite);
    std::puts("PROCESS_LIMIT_NATIVE_DIFFERENTIAL_PASS observations=32 owned_children=3");
}
