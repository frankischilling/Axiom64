// SPDX-License-Identifier: GPL-3.0-or-later
#include "fs/proc/ipv4.hpp"
#include "fs/proc/integer.hpp"
#include "net/ipv4/multicast_runtime.hpp"

namespace ax::proc4 {
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
