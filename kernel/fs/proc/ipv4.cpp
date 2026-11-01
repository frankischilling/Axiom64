// SPDX-License-Identifier: GPL-3.0-or-later
#include "fs/proc/ipv4.hpp"
#include "fs/proc/integer.hpp"
#include "net/ipv4/configuration.hpp"
#include "net/ipv4/multicast_runtime.hpp"

namespace ax::proc4 {
namespace {
constexpr ip4::ConfigurationKey keys[] = {ip4::ConfigurationKey::accept_source_route,
                                          ip4::ConfigurationKey::forwarding};
}

const char* property_name(unsigned property) {
    static constexpr const char* names[] = {"accept_source_route", "forwarding"};
    return property < property_count ? names[property] : nullptr;
}

const char* scope_name(unsigned cookie) {
    if (cookie < 3)
        return cookie == 0 ? "all" : cookie == 1 ? "default" : "lo";
    auto info = cookie - 2 <= max_net_devices ? net_info(cookie - 2) : nullptr;
    return info && ip4::configuration_generation(info->index) ? info->name : nullptr;
}

bool scope_index(const char* name, unsigned& index) {
    if (!strcmp(name, "all"))
        index = ip4::configuration_all;
    else if (!strcmp(name, "default"))
        index = ip4::configuration_default;
    else if (!strcmp(name, "lo"))
        index = ipv4_loopback;
    else {
        for (unsigned at = 1; at <= max_net_devices; at++)
            if (auto info = net_info(at); info && !strcmp(info->name, name)) {
                index = at;
                return true;
            }
        return false;
    }
    return true;
}

uint64_t scope_generation(unsigned index) {
    return ip4::configuration_generation(index);
}

int64_t read(unsigned index, unsigned property, uint64_t& offset, void* output, size_t length) {
    if (property >= property_count)
        return -22;
    int32_t value;
    if (int error = ip4::configuration_read(index, keys[property], value))
        return error;
    return proc::read_integer(value, offset, output, length);
}

int64_t write(unsigned index, unsigned property, uint64_t& offset, const void* input,
              size_t length) {
    if (property >= property_count)
        return -22;
    if (!length)
        return 0;
    if (offset) {
        offset += length;
        return int64_t(length);
    }
    int32_t value;
    size_t consumed = 0, parsed = min(length, size_t(4095));
    if (!proc::parse_integer(static_cast<const char*>(input), parsed, false, value, consumed))
        return -22;
    if (int error = ip4::configuration_write(index, keys[property], value))
        return error;
    consumed += length - parsed;
    offset += consumed;
    return int64_t(consumed);
}

int64_t source_limit_read(uint64_t& offset, void* output, size_t length) {
    return proc::read_integer(ipv4_multicast_source_limit(), offset, output, length);
}

int64_t source_limit_write(uint64_t& offset, const void* input, size_t length) {
    if (!length)
        return 0;
    if (offset) {
        offset += length;
        return int64_t(length);
    }
    int32_t value;
    size_t consumed = 0, parsed = min(length, size_t(4095));
    if (!proc::parse_integer(static_cast<const char*>(input), parsed, false, value, consumed))
        return -22;
    ipv4_multicast_source_limit(value);
    consumed += length - parsed;
    offset += consumed;
    return int64_t(consumed);
}
} // namespace ax::proc4
