// SPDX-License-Identifier: GPL-3.0-or-later
#include "net/ipv6/reassembly.hpp"
#include "core/base.hpp"
#include <new>

namespace ax::ip6 {
namespace {
constexpr size_t maximum_payload = 65535;
constexpr size_t blocks = (maximum_payload + 7) / 8;

struct Queue {
    Address source, destination;
    unsigned key_index = 0, index = 0;
    uint32_t identification = 0, previous_header = 6;
    uint64_t expires = 0;
    size_t received = 0, highest = 0, final_length = 0, nonfinal_end = 0;
    uint8_t ecn = 0, protocol = 59;
    uint8_t* prefix = nullptr;
    size_t prefix_length = 0, quote_length = 0;
    uint8_t quote[1232]{};
    uint16_t lengths[blocks]{};
    uint8_t more[(blocks + 7) / 8]{}, present[(maximum_payload + 7) / 8]{};
    uint8_t payload[maximum_payload]{};
};

Queue* queues[reassembly_capacity]{};

void clear(Queue*& slot) {
    auto queue = slot;
    slot = nullptr;
    if (queue) {
        release(queue->prefix);
        release(queue);
    }
}

Reassembled reject(Queue*& slot) {
    clear(slot);
    return {};
}

bool covered(const Queue& queue, size_t offset) {
    return queue.present[offset / 8] & (1u << (offset % 8));
}

bool first_headers(const Packet& packet) {
    const auto data = packet.payload;
    size_t at = 0;
    uint8_t protocol = packet.protocol;
    while (protocol == 0 || protocol == 43 || protocol == 44 || protocol == 60 || protocol == 51) {
        // Hop-by-Hop cannot follow Fragment; nested Fragment is never valid.
        if (protocol == 0 || protocol == 44 || packet.length - at < 8)
            return false;
        size_t length =
            protocol == 51 ? (size_t(data[at + 1]) + 2) * 4 : (size_t(data[at + 1]) + 1) * 8;
        if (length > packet.length - at)
            return false;
        protocol = data[at];
        at += length;
    }
    size_t available = packet.length - at;
    if (protocol == 6) {
        if (available < 20)
            return false;
        size_t header = size_t(data[at + 12] >> 4) * 4;
        return header >= 20 && header <= available;
    }
    return (protocol != 17 && protocol != 58 && protocol != 50) || available >= 8;
}

void put16(uint8_t* bytes, size_t value) {
    bytes[0] = value >> 8;
    bytes[1] = value;
}
} // namespace

void reassembly_expire(uint64_t now, FragmentExpired expired) {
    for (auto& slot : queues) {
        if (!slot || now < slot->expires)
            continue;
        auto queue = slot;
        slot = nullptr;
        if (expired && queue->quote_length)
            expired(queue->index, queue->quote, queue->quote_length);
        clear(queue);
    }
}

void reassembly_discard(const Address* destination, unsigned index) {
    for (auto& queue : queues)
        if (queue && (!destination || (queue->destination == *destination &&
                                       (!queue->key_index || !index || queue->key_index == index))))
            clear(queue);
}

Reassembled reassemble(unsigned index, const uint8_t* bytes, size_t length, uint64_t now,
                       FragmentExpired expired) {
    reassembly_expire(now, expired);
    auto packet = decode(bytes, length);
    if (!index)
        return {};
    if (packet.input == Input::payload || packet.input == Input::no_next_header)
        return {FragmentStatus::whole};
    if (packet.input == Input::parameter_problem && packet.fragment.header_offset)
        return {FragmentStatus::parameter_problem, nullptr, 0, packet.error_pointer,
                packet.error_code};
    if (packet.input != Input::fragment)
        return {};
    unsigned key_index =
        packet.header.destination.multicast() || packet.header.destination.link_local() ? index : 0;
    Queue** match = nullptr;
    Queue** empty = nullptr;
    for (auto& queue : queues) {
        if (queue && queue->source == packet.header.source &&
            queue->destination == packet.header.destination &&
            queue->identification == packet.fragment.identification &&
            queue->key_index == key_index)
            match = &queue;
        else if (!queue && !empty)
            empty = &queue;
    }
    size_t offset = packet.fragment.offset, end = offset + packet.length;
    if (!packet.length) {
        if (match)
            clear(*match);
        return {};
    }
    if (!offset && !first_headers(packet)) {
        if (match)
            clear(*match);
        return {FragmentStatus::parameter_problem, nullptr, 0, 0, 3};
    }
    if (!match) {
        if (!empty)
            return {FragmentStatus::exhausted};
        auto queue = static_cast<Queue*>(alloc(sizeof(Queue)));
        if (!queue)
            return {FragmentStatus::exhausted};
        new (queue) Queue{};
        queue->source = packet.header.source;
        queue->destination = packet.header.destination;
        queue->key_index = key_index;
        queue->index = index;
        queue->identification = packet.fragment.identification;
        queue->expires =
            now > UINT64_MAX - reassembly_lifetime ? UINT64_MAX : now + reassembly_lifetime;
        *empty = queue;
        match = empty;
    }
    auto& slot = *match;
    auto& queue = *slot;
    if ((queue.final_length &&
         (end > queue.final_length || (packet.fragment.more && end == queue.final_length))) ||
        (!packet.fragment.more && ((queue.final_length && end != queue.final_length) ||
                                   end < queue.highest || end <= queue.nonfinal_end)))
        return reject(slot);
    size_t prefix = offset ? queue.prefix_length : packet.fragment.header_offset;
    if (prefix && (end > maximum_payload - (prefix - header_size) ||
                   queue.highest > maximum_payload - (prefix - header_size))) {
        clear(slot);
        return {FragmentStatus::parameter_problem, nullptr, 0, packet.fragment.header_offset + 2,
                0};
    }
    size_t present = 0;
    for (size_t at = offset; at < end; at++)
        present += covered(queue, at);
    if (present) {
        unsigned block = offset / 8;
        bool more = queue.more[block / 8] & (1u << (block % 8));
        if (present == packet.length && queue.lengths[block] == packet.length &&
            more == packet.fragment.more &&
            !memcmp(queue.payload + offset, packet.payload, packet.length))
            return {FragmentStatus::duplicate};
        return reject(slot);
    }
    uint8_t ecn = queue.ecn | uint8_t(1u << (packet.header.traffic_class & 3));
    if ((ecn & 1) && ecn != 1)
        return reject(slot);
    if (!offset) {
        queue.prefix = static_cast<uint8_t*>(alloc(prefix));
        if (!queue.prefix) {
            clear(slot);
            return {FragmentStatus::exhausted};
        }
        queue.prefix_length = prefix;
        queue.previous_header = packet.fragment.previous_header_offset;
        queue.protocol = packet.protocol;
        queue.index = index;
        memcpy(queue.prefix, bytes, prefix);
        queue.quote_length = min(size_t(packet.size), sizeof(queue.quote));
        memcpy(queue.quote, bytes, queue.quote_length);
    }
    queue.ecn = ecn;
    if (packet.fragment.more) {
        queue.nonfinal_end = max(queue.nonfinal_end, end);
        queue.more[offset / 64] |= uint8_t(1u << ((offset / 8) % 8));
    } else
        queue.final_length = end;
    queue.lengths[offset / 8] = packet.length;
    queue.highest = max(queue.highest, end);
    memcpy(queue.payload + offset, packet.payload, packet.length);
    for (size_t at = offset; at < end; at++)
        queue.present[at / 8] |= uint8_t(1u << (at % 8));
    queue.received += packet.length;
    if (!queue.prefix || !queue.final_length || queue.received != queue.final_length)
        return {FragmentStatus::pending};
    size_t total = queue.prefix_length + queue.final_length;
    auto output = static_cast<uint8_t*>(alloc(total));
    if (!output) {
        clear(slot);
        return {FragmentStatus::exhausted};
    }
    memcpy(output, queue.prefix, queue.prefix_length);
    memcpy(output + queue.prefix_length, queue.payload, queue.final_length);
    output[queue.previous_header] = queue.protocol;
    put16(output + 4, total - header_size);
    if (queue.ecn & 8)
        output[1] |= 0x30;
    clear(slot);
    return {FragmentStatus::complete, output, total};
}
} // namespace ax::ip6
