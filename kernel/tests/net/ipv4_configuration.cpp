// SPDX-License-Identifier: GPL-3.0-or-later
#include "net/ipv4/configuration.hpp"
#include "fs/proc/ipv4.hpp"
#include <cassert>
#include <cstdio>
#include <cstdlib>

namespace {
ax::NetInfo links[2];
unsigned present = 0;
} // namespace

namespace ax {
const NetInfo* net_info(unsigned index) {
    return index && index <= present ? &links[index - 1] : nullptr;
}

int32_t ipv4_multicast_source_limit() {
    std::abort();
}

void ipv4_multicast_source_limit(int32_t) {
    std::abort();
}
} // namespace ax

using namespace ax;
using namespace ax::ip4;

static int32_t value(unsigned index, ConfigurationKey key) {
    int32_t result;
    assert(!configuration_read(index, key, result));
    return result;
}

int main() {
    constexpr auto source = ConfigurationKey::accept_source_route;
    constexpr auto forward = ConfigurationKey::forwarding;
    assert(!value(configuration_all, source) && value(configuration_default, source) == 1);
    assert(!configuration_source_route(ipv4_loopback) && !configuration_forwarding(ipv4_loopback));
    assert(!configuration_generation(1) && !configuration_generation(10));
    int32_t untouched = 123;
    assert(configuration_read(1, source, untouched) == -19 && untouched == 123);
    assert(configuration_write(1, forward, 1) == -19);
    assert(configuration_write(configuration_all, ConfigurationKey(99), 1) == -22);
    assert(!configuration_write(configuration_default, source, -1));
    assert(!configuration_write(configuration_default, forward, 2));
    links[0].index = 1;
    memcpy(links[0].name, "eth0", 5);
    present = 1;
    configuration_registered(1);
    auto generation = configuration_generation(1);
    assert(value(1, source) == -1 && value(1, forward) == 2);
    assert(value(ipv4_loopback, source) == 1 && value(ipv4_loopback, forward) == 0);
    assert(!configuration_write(configuration_all, source, 1));
    assert(configuration_source_route(1));
    assert(!configuration_write(1, source, 0) && !configuration_source_route(1));
    assert(!configuration_write(configuration_default, source, INT32_MIN));
    assert(!value(1, source));
    assert(!configuration_write(configuration_all, forward, INT32_MAX));
    assert(value(1, forward) == INT32_MAX && value(ipv4_loopback, forward) == INT32_MAX);
    assert(!configuration_write(1, forward, 0));
    assert(!configuration_write(configuration_default, forward, -1));
    assert(!configuration_write(configuration_all, forward, INT32_MAX));
    assert(!value(1, forward) && value(configuration_default, forward) == -1);
    assert(configuration_forwarding(ipv4_loopback) && !configuration_forwarding(1));
    assert(!configuration_write(configuration_all, forward, INT32_MIN));
    assert(value(1, forward) == INT32_MIN && value(configuration_default, forward) == INT32_MIN);
    assert(configuration_forwarding(1));
    assert(configuration_generation(1) == generation);
    configuration_registered(1);
    assert(configuration_generation(1) > generation && value(1, source) == INT32_MIN);
    unsigned index;
    assert(proc4::scope_index("eth0", index) && index == 1);
    assert(!proc4::scope_index("eth1", index));
    assert(!strcmp(proc4::scope_name(3), "eth0") && !proc4::scope_name(4));
    assert(!proc4::scope_name(UINT32_MAX));
    assert(!proc4::property_name(2));
    uint64_t offset = 0;
    const char text[] = "1 trailing\n";
    assert(proc4::write(1, 0, offset, text, sizeof(text) - 1) == 2 && offset == 2);
    assert(value(1, source) == 1);
    assert(proc4::write(1, 0, offset, "0\n", 2) == 2 && offset == 4 && value(1, source) == 1);
    offset = 0;
    assert(proc4::write(1, 0, offset, "2147483648\n", 11) == -22 && !offset);
    assert(proc4::write(1, 0, offset, "010\n", 4) == 4 && value(1, source) == 8);
    char output[32]{};
    offset = 0;
    assert(proc4::read(1, 0, offset, output, sizeof(output)) == 2 && !strcmp(output, "8\n"));
    assert(!proc4::read(1, 0, offset, output, sizeof(output)));
    generation = configuration_generation(1);
    configuration_reset();
    assert(configuration_generation(1) > generation);
    assert(!value(configuration_all, source) && value(1, source) == 1 && !value(1, forward));
    puts("IPV4_CONFIGURATION_MODEL_PASS");
}
