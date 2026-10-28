// SPDX-License-Identifier: GPL-3.0-or-later
#include "source_options.hpp"
#include "net/ipv4_wire.hpp"
#include "process/task.hpp"
#include "../socket.hpp"

namespace ax {
namespace {
constexpr unsigned legacy_filter = 41, generic_filter = 48;
constexpr unsigned maximum_option_bytes = 131072;

uint16_t native16(const uint8_t* bytes) {
    uint16_t value;
    memcpy(&value, bytes, sizeof(value));
    return value;
}

uint32_t native32(const uint8_t* bytes) {
    uint32_t value;
    memcpy(&value, bytes, sizeof(value));
    return value;
}

void native32(uint8_t* bytes, uint32_t value) {
    memcpy(bytes, &value, sizeof(value));
}

bool output(Task& task, uint64_t pointer, const void* data, size_t length) {
    auto bytes = static_cast<const uint8_t*>(data);
    while (length) {
        size_t count = min(length, size_t(page_size - pointer % page_size));
        if (!task.memory->space.copy_out(pointer, bytes, count))
            return false;
        bytes += count;
        pointer += count;
        length -= count;
    }
    return true;
}

int interface(MulticastInterface select, unsigned requested, uint32_t address, uint32_t group,
              unsigned& index) {
    int error = select(requested, address, group, index);
    // The source APIs resolve through the multicast device lookup, which
    // reports ENODEV for an interface address not owned by this network stack.
    return error == -99 ? -19 : error;
}

int get(Task& task, const Frame& frame, InetSocket* socket, ip4::MulticastHost& host,
        MulticastInterface select) {
    uint32_t length;
    if (!task.memory->space.copy_in(&length, frame.r8, sizeof(length)))
        return -14;
    if (int32_t(length) < 0)
        return -22;
    unsigned option = unsigned(frame.rdx);
    if (option != legacy_filter && option != generic_filter)
        return -92;
    bool generic = option == generic_filter;
    unsigned prefix = generic ? 144 : 16;
    if (length < prefix)
        return -22;
    uint8_t header[144]{};
    if (!task.memory->space.copy_in(header, frame.r10, prefix))
        return -14;
    if (generic && native16(header + 8) != 2)
        return -22;
    uint32_t group = ip4::get32(header + (generic ? 12 : 0));
    if (!ip4::multicast(group))
        return -22;
    unsigned index = native32(header);
    if (!generic) {
        if (int error = interface(select, 0, ip4::get32(header + 4), group, index))
            return error;
    }
    auto filter = host.filter(socket->multicast, index, group);
    if (!filter)
        return -99;
    uint32_t sources[64];
    unsigned count = filter->sources(sources, 64);
    unsigned copied = min(count, native32(header + (generic ? 140 : 12)));
    unsigned stride = generic ? 128 : 4;
    uint32_t actual = prefix + copied * stride;
    native32(header + (generic ? 136 : 8), filter->mode());
    native32(header + (generic ? 140 : 12), count);
    auto source_output = [&]() {
        for (unsigned n = 0; n < copied; n++) {
            uint8_t address[128]{};
            if (generic) {
                address[0] = 2;
                ip4::put32(address + 4, sources[n]);
            } else
                ip4::put32(address, sources[n]);
            if (!output(task, frame.r10 + prefix + uint64_t(n) * stride, address, stride))
                return false;
        }
        return true;
    };
    // The generic API writes source records before publishing the result
    // length/header. The legacy API publishes length/header before sources.
    // optlen bounds the required input prefix; requested count bounds copying.
    if (generic && !source_output())
        return -14;
    if (!output(task, frame.r8, &actual, sizeof(actual)) ||
        !output(task, frame.r10, header, prefix))
        return -14;
    return !generic && !source_output() ? -14 : 0;
}

struct OptionBytes {
    uint8_t* data;

    ~OptionBytes() {
        release(data);
    }
};

int replace(Task& task, const Frame& frame, InetSocket* socket, ip4::MulticastHost& host,
            MulticastInterface select, unsigned limit) {
    bool generic = frame.rdx == generic_filter;
    unsigned prefix = generic ? 144 : 16, stride = generic ? 128 : 4;
    unsigned length = unsigned(frame.r8);
    if (length < prefix)
        return -22;
    if (length > maximum_option_bytes)
        return -105;
    OptionBytes owned{static_cast<uint8_t*>(alloc(length))};
    if (!owned.data)
        return -12;
    // Copy the entire supplied option, including ignored padding, before
    // validating fields or changing ownership. This retains copy-fault order.
    if (!task.memory->space.copy_in(owned.data, frame.r10, length))
        return -14;
    const uint8_t* request = owned.data;
    unsigned count = native32(request + (generic ? 140 : 12));
    if (count > limit || count > ip4::MulticastSourceFilter::capacity)
        return -105;
    if (length < prefix + count * stride)
        return -22;
    if (generic && native16(request + 8) != 2)
        return -99;
    uint32_t addresses[64];
    for (unsigned n = 0; n < count; n++) {
        const uint8_t* source = request + prefix + n * stride;
        if (generic && native16(source) != 2)
            return -99;
        addresses[n] = ip4::get32(source + (generic ? 4 : 0));
    }
    uint32_t group = ip4::get32(request + (generic ? 12 : 0));
    unsigned mode = native32(request + (generic ? 136 : 8));
    if (!ip4::multicast(group) || mode > 1)
        return -22;
    unsigned index = 0;
    if (int error = interface(select, generic ? native32(request) : 0,
                              generic ? 0 : ip4::get32(request + 4), group, index))
        return error;
    return host.replace(socket->multicast, index, group, mode, addresses, count, limit, ticks);
}
} // namespace

int multicast_source_option(Task& task, const Frame& frame, InetSocket* socket,
                            ip4::MulticastHost& host, MulticastInterface select,
                            unsigned source_limit) {
    if (frame.rax == 55)
        return get(task, frame, socket, host, select);
    if (int32_t(frame.r8) < 0)
        return -22;
    unsigned option = unsigned(frame.rdx), length = unsigned(frame.r8);
    if (option == legacy_filter || option == generic_filter)
        return replace(task, frame, socket, host, select, source_limit);
    bool generic = option >= 42;
    bool membership = option == 42 || option == 45;
    unsigned required = generic ? (membership ? 136 : 264) : 12;
    if ((membership && length < required) || (!membership && length != required))
        return -22;
    uint8_t request[264]{};
    if (!task.memory->space.copy_in(request, frame.r10, required))
        return -14;
    if (generic && (native16(request + 8) != 2 || (!membership && native16(request + 136) != 2)))
        return membership ? -22 : -99;
    uint32_t group = ip4::get32(request + (generic ? 12 : 0));
    if (!ip4::multicast(group))
        return -22;
    unsigned index = 0;
    if (int error = interface(select, generic ? native32(request) : 0,
                              generic ? 0 : ip4::get32(request + 4), group, index))
        return error;
    if (membership)
        return option == 42 ? host.join(socket->multicast, index, group, ticks)
                            : host.leave(socket->multicast, index, group, ticks);
    bool include = option == 39 || option == 40 || option == 46 || option == 47;
    bool add = option == 38 || option == 39 || option == 43 || option == 46;
    uint32_t source = ip4::get32(request + (generic ? 140 : 8));
    return host.source(socket->multicast, index, group, include, add, source, source_limit, ticks);
}
} // namespace ax
