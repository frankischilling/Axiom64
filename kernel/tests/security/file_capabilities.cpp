// SPDX-License-Identifier: GPL-3.0-or-later
#include "security/file_capabilities.hpp"
#include "security/credentials.hpp"
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace ax {
void* alloc(size_t size) {
    return std::malloc(size);
}

void release(void* pointer) {
    std::free(pointer);
}
} // namespace ax

using namespace ax;
constexpr uint64_t bind_port = 1ull << 10, raw_socket = 1ull << 13;

static void put(uint8_t* data, uint32_t value) {
    for (unsigned i = 0; i < 4; i++)
        data[i] = value >> (i * 8);
}

static void formats() {
    uint8_t data[24]{}, output[32];
    FileCapabilities caps;
    for (unsigned revision = 1; revision <= 3; revision++) {
        size_t length = revision == 1 ? 12 : revision == 2 ? 20 : 24;
        memset(data, 0, sizeof(data));
        put(data, (revision << 24) | 1);
        put(data + 4, bind_port);
        put(data + 8, raw_socket);
        assert(file_capabilities_decode(data, length, caps) == 0);
        assert(caps.present && caps.effective && caps.permitted == bind_port &&
               caps.inheritable == raw_socket && !caps.root_id);
        for (size_t size = 0; size <= 32; size++)
            if (size != length) {
                FileCapabilities unchanged{99, 88, 77, true, true};
                // Oversized lengths are rejected before looking past the header.
                assert(file_capabilities_decode(data, size, unchanged) == -22);
                assert(unchanged.permitted == 99 && unchanged.root_id == 77);
            }
        int expected = revision == 1 ? -22 : 0;
        assert(file_capabilities_decode(data, length, caps, FileCapabilityUse::write) == expected);
        memset(output, 0x5a, sizeof(output));
        int64_t exported = revision == 1 ? -22 : 20;
        assert(file_capabilities_export(data, length, output, 0) == exported);
        if (revision != 1) {
            assert(file_capabilities_export(data, length, output, 19) == -34);
            assert(output[0] == 0x5a);
            assert(file_capabilities_export(data, length, output, 20) == 20 && output[3] == 2);
            assert(!memcmp(output + 4, data + 4, 16));
            assert(output[20] == 0x5a);
        }
    }
    assert(file_capabilities_decode(nullptr, 24, caps) == -22);
    put(data, 0x03000001);
    put(data + 20, 1000);
    assert(file_capabilities_decode(data, 24, caps, FileCapabilityUse::write) == 0);
    assert(caps.root_id == 1000);
    assert(file_capabilities_export(data, 24, output, 24) == 24 && !memcmp(data, output, 24));
    put(data + 20, UINT32_MAX);
    assert(file_capabilities_decode(data, 24, caps, FileCapabilityUse::write) == 0 &&
           caps.root_id == UINT32_MAX);
    assert(file_capabilities_export(data, 24, output, 0) == -75);
    assert(file_capabilities_decode(data, 24, caps) == 0 && caps.root_id == UINT32_MAX);
    put(data + 20, 0);
    put(data, 0x03000003);
    assert(file_capabilities_decode(data, 24, caps, FileCapabilityUse::write) == -22);
    assert(file_capabilities_export(data, 24, output, 0) == -22);
    assert(file_capabilities_decode(data, 24, caps) == 0 && caps.effective);
    put(data, 0x03000001);
    put(data + 12, UINT32_MAX);
    put(data + 16, UINT32_MAX);
    assert(file_capabilities_decode(data, 24, caps) == 0);
    assert(!(caps.permitted & ~all_capabilities) && !(caps.inheritable & ~all_capabilities));
    // Bounded byte decoding covers arbitrary alignment, headers and lengths.
    uint32_t random = 0x31415926;
    uint8_t arbitrary[34];
    for (unsigned cycle = 0; cycle < 50000; cycle++) {
        for (auto& byte : arbitrary) {
            random ^= random << 13;
            random ^= random >> 17;
            random ^= random << 5;
            byte = random;
        }
        size_t size = random % 29;
        int error = file_capabilities_decode(arbitrary + (cycle & 3), size, caps);
        assert(error == 0 || error == -22);
    }
}

static Credentials ordinary() {
    Credentials value;
    value.user = {1000, 1000, 1000, 1000};
    value.group = {1000, 1000, 1000, 1000};
    value.permitted = value.effective = 0;
    return value;
}

static void exec_policy() {
    auto old = ordinary();
    FileCapabilities file{bind_port, 0, 0, true, true};
    auto run = [&](uint32_t mode = 0100755, bool nosuid = false) {
        return credential_exec_file(old, 0, 0, mode, nosuid, file);
    };
    auto result = run();
    assert(!result.error && result.secure && result.value.permitted == bind_port &&
           result.value.effective == bind_port && result.value.user.effective == 1000);
    assert(old.permitted == 0 && old.user.effective == 1000);
    old.bounding &= ~bind_port;
    result = run();
    assert(result.error == -1 && old.permitted == 0 && old.user.effective == 1000);
    // A capability-aware file may start with its permitted capability bounded out.
    file.effective = false;
    result = run();
    assert(!result.error && !result.value.permitted && !result.value.effective && !result.secure);
    // File inheritable capabilities are admitted through the task inheritable set.
    old.inheritable = bind_port;
    file.inheritable = bind_port;
    file.effective = true;
    result = run();
    assert(!result.error && result.value.permitted == bind_port &&
           result.value.effective == bind_port);
    old = ordinary();
    old.no_new_privileges = true;
    result = run();
    assert(!result.error && !result.value.permitted && !result.value.effective && result.secure);
    old.no_new_privileges = false;
    result = run(0104755, true);
    assert(!result.error && result.value.user.effective == 1000 && !result.value.permitted &&
           !result.secure);
    old.permitted = old.inheritable = old.ambient = raw_socket;
    file = {};
    result = run();
    assert(!result.error && result.value.permitted == raw_socket &&
           result.value.effective == raw_socket && result.value.ambient == raw_socket &&
           !result.secure);
    file = {bind_port, 0, 0, true, true};
    result = run();
    assert(!result.error && result.value.permitted == bind_port && !result.value.ambient);
    // Stored capabilities for an unavailable namespace do not cancel ambient.
    file.root_id = 1000;
    result = run();
    assert(!result.error && result.value.permitted == raw_socket &&
           result.value.ambient == raw_socket);
    file.root_id = UINT32_MAX;
    result = run();
    assert(!result.error && result.value.permitted == raw_socket);
    old = ordinary();
    file = {bind_port, 0, 0, true, true};
    result = run(0104755);
    assert(!result.error && result.value.user.effective == 0 &&
           result.value.permitted == bind_port && result.value.effective == bind_port &&
           result.secure);
    file.present = false;
    result = run(0104755);
    assert(!result.error && result.value.permitted == all_capabilities &&
           result.value.effective == all_capabilities);
    old.securebits = 1 | 16;
    result = run(0104755);
    assert(!result.error && result.value.user.effective == 0 && !result.value.permitted &&
           !(result.value.securebits & 16));
    file = {0, 0, 0, true, true};
    old = ordinary();
    result = run();
    assert(!result.error && !result.value.permitted && result.secure);
    file.effective = false;
    result = run();
    assert(!result.error && !result.value.permitted && !result.secure);
    old = Credentials{};
    old.bounding = raw_socket;
    file = {bind_port, 0, 0, true, false};
    result = run();
    assert(!result.error && result.value.permitted == raw_socket &&
           result.value.effective == raw_socket);
    old.securebits = 1;
    result = run();
    assert(!result.error && !result.value.permitted && !result.value.effective);
    old = ordinary();
    old.permitted = bind_port;
    old.no_new_privileges = true;
    file = {bind_port, 0, 0, true, true};
    result = run();
    assert(!result.error && result.value.permitted == bind_port &&
           result.value.effective == bind_port && result.secure);
    assert(result.dumpable);
    old = ordinary();
    file = {bind_port, 0, 0, true, true};
    result = run();
    assert(!result.error && result.secure && !result.dumpable);
    old.permitted = old.inheritable = bind_port;
    file = {0, bind_port, 0, true, true};
    result = run();
    assert(!result.error && result.secure && result.dumpable);
    old = ordinary();
    file = {0, 0, 0, true, true};
    result = run();
    assert(!result.error && result.secure && result.dumpable);
    old.user.filesystem++;
    result = run();
    assert(!result.error && !result.dumpable);
}

int main() {
    formats();
    exec_policy();
    puts("FILE_CAPABILITIES_POLICY_PASS formats bounds malformed root_ids capability_exec "
         "failed_candidates");
}
