// SPDX-License-Identifier: GPL-3.0-or-later
#include "net/ipv4/multicast_runtime.hpp"
#include "source_options.hpp"
#include "net/ipv4.hpp"
#include "net/ipv4_wire.hpp"
#include "net/socket_options.hpp"
#include "process/task.hpp"
#include "core/random.hpp"
#include "../socket.hpp"

namespace ax {
namespace {
static_assert(ipv4_loopback < ip4::MulticastHost::interface_capacity);
ip4::MulticastHost host;
bool seeded;
int32_t source_limit = 10;

void refresh() {
    for (unsigned index = 1; index <= max_net_devices; index++) {
        auto info = net_info(index);
        host.link(index, info && info->live && info->administrative && info->carrier, ticks,
                  info ? info->mtu : 68);
    }
    host.link(ipv4_loopback, true, ticks, 65535);
}

unsigned address_index(uint32_t address) {
    if ((address >> 24) == 127)
        return ipv4_loopback;
    for (unsigned n = 0; auto entry = ipv4_address(n); n++)
        if (entry->config.address == address)
            return entry->index;
    return 0;
}

int selected_interface(unsigned requested, uint32_t address, uint32_t group, unsigned& index) {
    if (int32_t(requested) < 0)
        return -19;
    index = requested;
    if (!index && address) {
        index = address_index(address);
        if (!index)
            return -99;
    }
    if (index) {
        if (index != ipv4_loopback && !net_info(index))
            return -19;
        return 0;
    }
    Ipv4Path path;
    int error = ipv4_path(0, group, 0, path);
    if (error)
        return -19;
    index = path.index;
    return 0;
}

void prepare() {
    if (!seeded) {
        uint32_t seed = 0;
        if (!random_read(&seed, sizeof(seed), true))
            host.seed(seed);
        seeded = true;
    }
    refresh();
}

bool emit(void*, unsigned index, uint32_t destination, const uint8_t* bytes, size_t length) {
    // Loopback has no neighboring multicast router or Ethernet transmission.
    return index == ipv4_loopback || ipv4_multicast_report(index, destination, bytes, length);
}
} // namespace

int32_t ipv4_multicast_source_limit() {
    return source_limit;
}

void ipv4_multicast_source_limit(int32_t value) {
    source_limit = value;
}

bool ipv4_multicast_member(unsigned index, uint32_t group) {
    refresh();
    return host.member(index, group);
}

bool ipv4_multicast_source_allowed(unsigned index, uint32_t group, uint32_t source) {
    refresh();
    return host.accepts_source(index, group, source);
}

bool inet_multicast_accepts(const InetSocket* socket, unsigned index, uint32_t group,
                            uint32_t source) {
    return host.accepts(socket->multicast, index, group, source);
}

bool inet_multicast_loop(const InetSocket* socket) {
    return !socket || socket->multicast.loop;
}

void inet_multicast_close(InetSocket* socket) {
    host.close(socket->multicast, ticks);
}

void ipv4_multicast_poll() {
    refresh();
    host.poll(ticks, emit, nullptr);
}

void ipv4_multicast_input(unsigned index, const uint8_t* bytes, size_t length) {
    size_t header = size_t(bytes[0] & 15) * 4;
    if (bytes[8] != 1 || (ip4::get16(bytes + 6) & 0x3fff))
        return;
    bool alert = false;
    for (size_t offset = 20; offset < header;) {
        uint8_t type = bytes[offset];
        if (!type)
            break;
        if (type == 1) {
            offset++;
            continue;
        }
        if (offset + 2 > header || bytes[offset + 1] < 2 || bytes[offset + 1] > header - offset)
            return;
        if (type != 0x94 || bytes[offset + 1] != 4 || bytes[offset + 2] || bytes[offset + 3])
            return;
        alert = true;
        offset += 4;
    }
    refresh();
    host.receive(index, ip4::get32(bytes + 16), bytes + header, length - header, alert, ticks);
}

int inet_multicast_option(Task& task, const Frame& frame, InetSocket* socket) {
    unsigned option = unsigned(frame.rdx);
    auto& owner = socket->multicast;
    if (option >= 37 && option <= 48) {
        if (frame.rax == 54)
            prepare();
        return multicast_source_option(task, frame, socket, host, selected_interface,
                                       unsigned(source_limit));
    }
    if (frame.rax == 55) {
        if (option == 35 || option == 36)
            return -92;
        uint32_t length;
        if (!task.memory->space.copy_in(&length, frame.r8, 4))
            return -14;
        if (int32_t(length) < 0)
            return -22;
        int value = option == 32   ? int(__builtin_bswap32(owner.output_address))
                    : option == 33 ? owner.ttl
                    : option == 34 ? owner.loop
                                   : owner.all;
        uint32_t capacity = min(length, uint32_t(4));
        if ((option == 33 || option == 34) && capacity < 4 && capacity)
            capacity = 1;
        return socket_integer_result(task, value, capacity, frame.r10, frame.r8);
    }
    if (socket->type == 1 && (option == 32 || option == 33))
        return -22;
    int32_t length = int32_t(frame.r8);
    if (length < 0)
        return -22;
    if (option == 32 || option == 35 || option == 36) {
        if (socket->type == 1 && option != 32)
            return -71;
        uint8_t request[12]{};
        size_t count = length >= 12 ? 12 : length >= 8 ? 8 : 4;
        if (length < (option == 32 ? 4 : 8))
            return -22;
        if (!task.memory->space.copy_in(request, frame.r10, count))
            return -14;
        uint32_t group = option == 32 ? 0xe0000001 : ip4::get32(request);
        uint32_t address =
            option == 32 && count == 4 ? ip4::get32(request) : ip4::get32(request + 4);
        unsigned requested = 0;
        if (count == 12)
            memcpy(&requested, request + 8, 4);
        if (option != 32 && !ip4::multicast(group))
            return -22;
        if (option == 36) {
            if (!requested && address) {
                requested = address_index(address);
                if (!requested)
                    return -99;
            }
            return host.leave(owner, requested, group, ticks);
        }
        unsigned index = 0;
        // An all-zero output request restores route-based selection.
        if (option == 32 && !requested && !address) {
            owner.output_index = 0;
            owner.output_address = 0;
            socket->destination = {};
            return 0;
        }
        int error = selected_interface(requested, address, group, index);
        if (error)
            return error;
        if (option == 32) {
            if (socket->index && socket->index != index)
                return -22;
            owner.output_index = index;
            owner.output_address = address;
            socket->destination = {};
            return 0;
        }
        prepare();
        return host.join(owner, index, group, ticks);
    }
    if (!length)
        return -22;
    int value = 0;
    size_t bytes = length >= 4 ? 4 : 1;
    if (!task.memory->space.copy_in(&value, frame.r10, bytes))
        return -14;
    if (option == 33) {
        if (value < -1 || value > 255)
            return -22;
        owner.ttl = value == -1 ? 1 : value;
    } else if (option == 34)
        owner.loop = value != 0;
    else {
        if (value != 0 && value != 1)
            return -22;
        owner.all = value != 0;
    }
    return 0;
}
} // namespace ax
