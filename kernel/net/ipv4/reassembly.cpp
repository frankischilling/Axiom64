// SPDX-License-Identifier: GPL-3.0-or-later
#include "net/ipv4/reassembly.hpp"
#include "net/ipv4_wire.hpp"
#include "core/base.hpp"
#include <new>

namespace ax::ip4 {
namespace {
constexpr size_t maximum_payload = 65535 - 20;

struct Queue {
    uint32_t source, destination;
    unsigned index;
    uint16_t identifier;
    uint8_t protocol, header_length, ecn;
    bool link_broadcast;
    bool options_processed;
    ReceivedOptions options;
    uint64_t expires;
    size_t received, highest, final_length, nonfinal_end;
    size_t largest_fragment, largest_df_fragment;
    uint8_t header[60];
    uint8_t present[(maximum_payload + 7) / 8];
    uint8_t payload[maximum_payload];
};

Queue* queues[reassembly_capacity]{};

bool matches(const Queue& queue, const uint8_t* packet) {
    return queue.source == get32(packet + 12) && queue.destination == get32(packet + 16) &&
           queue.identifier == get16(packet + 4) && queue.protocol == packet[9];
}

void clear(Queue*& queue) {
    auto old = queue;
    queue = nullptr;
    release(old);
}

Reassembled reject(Queue*& queue) {
    clear(queue);
    return {};
}

bool covered(const Queue& queue, size_t offset) {
    return queue.present[offset / 8] & (1u << (offset % 8));
}

bool header_valid(const uint8_t* packet, size_t available, size_t& header, size_t& total) {
    if (!packet || available < 20 || (packet[0] >> 4) != 4)
        return false;
    header = size_t(packet[0] & 15) * 4;
    total = get16(packet + 2);
    return header >= 20 && header <= available && total >= header && total <= available &&
           packet[8] && !(get16(packet + 6) & 0x8000) && !checksum(packet, header);
}
} // namespace

void reassembly_expire(uint64_t now, FragmentExpired expired) {
    for (auto& slot : queues) {
        if (!slot || now < slot->expires)
            continue;
        auto queue = slot;
        slot = nullptr;
        if (expired && queue->header_length) {
            uint8_t quote[68];
            memcpy(quote, queue->header, queue->header_length);
            memcpy(quote + queue->header_length, queue->payload, 8);
            expired(queue->index, quote, queue->header_length + 8, queue->link_broadcast);
        }
        release(queue);
    }
}

void reassembly_discard(uint32_t destination) {
    for (auto& queue : queues)
        if (queue && (!destination || queue->destination == destination))
            clear(queue);
}

Reassembled reassemble(unsigned index, const uint8_t* packet, size_t available, uint64_t now,
                       bool link_broadcast, FragmentExpired expired,
                       const ReceivedOptions* options) {
    reassembly_expire(now, expired);
    size_t header = 0, total = 0;
    if (!index || !header_valid(packet, available, header, total) ||
        (options && options->size() != header - 20))
        return {};
    uint16_t fragment = get16(packet + 6);
    size_t offset = size_t(fragment & 0x1fff) * 8;
    bool more = fragment & 0x2000;
    // Atomic IDs carry no reassembly identity (RFC 6864). Complete packets also
    // bypass fragment lookup on the Linux receive path.
    if (!offset && !more)
        return {FragmentStatus::whole};
    Queue** match = nullptr;
    Queue** empty = nullptr;
    for (auto& queue : queues) {
        if (queue && matches(*queue, packet))
            match = &queue;
        else if (!queue && !empty)
            empty = &queue;
    }
    size_t length = total - header;
    size_t end = offset + length;
    if (!length || (more && length % 8) || end > maximum_payload ||
        (!offset && end > 65535 - header)) {
        if (match)
            clear(*match);
        return {};
    }
    if (!match) {
        if (!empty)
            return {FragmentStatus::exhausted};
        auto memory = static_cast<Queue*>(alloc(sizeof(Queue)));
        if (!memory)
            return {FragmentStatus::exhausted};
        new (memory) Queue{};
        memory->source = get32(packet + 12);
        memory->destination = get32(packet + 16);
        memory->index = index;
        memory->identifier = get16(packet + 4);
        memory->protocol = packet[9];
        memory->expires =
            now > UINT64_MAX - reassembly_lifetime ? UINT64_MAX : now + reassembly_lifetime;
        *empty = memory;
        match = empty;
    }
    auto& slot = *match;
    auto& queue = *slot;
    if ((queue.final_length && (end > queue.final_length || (more && end == queue.final_length))) ||
        (!more && ((queue.final_length && end != queue.final_length) || end < queue.highest ||
                   end <= queue.nonfinal_end)) ||
        (queue.header_length && end > size_t(65535) - queue.header_length) ||
        (!offset && queue.highest > 65535 - header))
        return reject(slot);

    size_t present = 0;
    for (size_t i = offset; i < end; i++)
        present += covered(queue, i);
    if (present) {
        // Only a fully covered, identical retransmission is harmless. Partial
        // overlap and conflicting data retire the complete datagram, not one hole.
        if (present == length && !memcmp(queue.payload + offset, packet + header, length))
            return {FragmentStatus::duplicate};
        return reject(slot);
    }
    uint8_t ecn = queue.ecn | uint8_t(1u << (packet[1] & 3));
    // RFC 3168: mixing Not-ECT with an ECN-capable fragment is invalid.
    if ((ecn & 1) && ecn != 1)
        return reject(slot);
    queue.ecn = ecn;
    queue.link_broadcast |= link_broadcast;
    if (!offset) {
        queue.index = index;
        queue.header_length = header;
        memcpy(queue.header, packet, header);
        if (options) {
            queue.options = *options;
            queue.options_processed = true;
            memcpy(queue.header + 20, options->data(), options->size());
        }
    }
    if (more)
        queue.nonfinal_end = max(queue.nonfinal_end, end);
    else
        queue.final_length = end;
    queue.highest = max(queue.highest, end);
    queue.largest_fragment = max(queue.largest_fragment, total);
    if (fragment & 0x4000)
        queue.largest_df_fragment = max(queue.largest_df_fragment, total);
    memcpy(queue.payload + offset, packet + header, length);
    for (size_t i = offset; i < end; i++)
        queue.present[i / 8] |= uint8_t(1u << (i % 8));
    queue.received += length;
    if (!queue.header_length || !queue.final_length || queue.received != queue.final_length)
        return {FragmentStatus::pending};

    size_t size = queue.header_length + queue.final_length;
    auto bytes = static_cast<uint8_t*>(alloc(size));
    if (!bytes) {
        clear(slot);
        return {FragmentStatus::exhausted};
    }
    memcpy(bytes, queue.header, queue.header_length);
    memcpy(bytes + queue.header_length, queue.payload, queue.final_length);
    put16(bytes + 2, size);
    put16(bytes + 6, queue.largest_df_fragment == queue.largest_fragment ? 0x4000 : 0);
    if (queue.ecn & (1u << 3))
        bytes[1] |= 3; // Preserve a congestion mark from any accepted fragment.
    put16(bytes + 10, 0);
    put16(bytes + 10, checksum(bytes, queue.header_length));
    Reassembled result{FragmentStatus::complete, bytes,        size, queue.link_broadcast,
                       queue.options_processed,  queue.options};
    clear(slot);
    return result;
}
} // namespace ax::ip4
