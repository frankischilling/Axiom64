// SPDX-License-Identifier: GPL-3.0-or-later
#include "net/ipv6/errors.hpp"
#include "io/vectors.hpp"
#include "net/ipv6.hpp"
#include "process/task.hpp"
#include "receive_control.hpp"

namespace ax {
namespace {
using Vector = IoVector;

struct Message {
    uint64_t name;
    uint32_t name_length, padding;
    uint64_t vectors, count, control, control_length;
    uint32_t flags, padding2;
};

static_assert(sizeof(Vector) == 16 && sizeof(Message) == 56);

struct Owned {
    Vector small[8], *vectors = small;
    Inet6Error* record = nullptr;

    ~Owned() {
        if (vectors != small)
            release(vectors);
        release(record);
    }
};

bool copy_bytes(Task& task, uint64_t destination, const void* data, size_t length) {
    auto bytes = static_cast<const uint8_t*>(data);
    while (length) {
        size_t copied = min(length, size_t(page_size - destination % page_size));
        if (!task.memory->space.copy_out(destination, bytes, copied))
            return false;
        destination += copied;
        bytes += copied;
        length -= copied;
    }
    return true;
}

size_t control_out(Task& task, const Message& message, const Inet6Socket* socket,
                   const Inet6Error& record, uint32_t& flags) {
    Inet6ControlWriter output(task, message.control, message.control_length, flags);
    // Received ICMP errors retain their outer packet's controls. Local output
    // failures have no received header and return only the extended error.
    if (record.error.origin == 3) {
        output.metadata(socket, record.packet_destination, record.index, record.hops,
                        record.traffic_class);
        output.extensions(socket, inet6_error_bytes(&record) + record.length,
                          record.extension_length, record.extension_protocol);
        output.legacy_metadata(socket, record.hops);
    }
    uint8_t body[44];
    memcpy(body, &record.error, 16);
    memcpy(body + 16, &record.offender, 28);
    output.append(25, body, sizeof(body));
    return output.used;
}
} // namespace

int64_t inet6_receive_error(Task& task, Inet6Socket* socket, const Frame& call) {
    bool message_call = call.rax == 47;
    uint32_t input_flags = message_call ? call.rdx : call.r10;
    if (message_call && (input_flags & 0x80000000))
        return -22;
    Owned owned;
    Message message{};
    size_t count = 1;
    if (message_call) {
        if (!task.memory->space.copy_in(&message, call.rsi, sizeof(message)))
            return -14;
        if (message.name && int32_t(message.name_length) < 0)
            return -22;
        if (message.count > 1024)
            return -90;
        count = message.count;
        if (count > 8) {
            owned.vectors = static_cast<Vector*>(alloc(count * sizeof(Vector)));
            if (!owned.vectors)
                return -12;
        }
        if (count &&
            !task.memory->space.copy_in(owned.vectors, message.vectors, count * sizeof(Vector)))
            return -14;
    } else {
        owned.vectors[0] = {call.rsi, min(call.rdx, uint64_t(0x7ffff000))};
        message.name = call.r8;
    }
    int64_t bounded = bound_io_vectors(owned.vectors, count);
    if (bounded < 0)
        return bounded;
    size_t capacity = bounded;
    net_poll();
    owned.record = inet6_take_error(socket);
    if (!owned.record)
        return -11;
    auto& record = *owned.record;
    uint32_t flags = 0x2000 | (input_flags & 0x40000000);
    if (record.length > capacity)
        flags |= 0x20;
    size_t copied = min(record.length, capacity), at = 0;
    for (size_t n = 0; n < count && at < copied; n++) {
        size_t length = min(owned.vectors[n].length, copied - at);
        if (!copy_bytes(task, owned.vectors[n].base, inet6_error_bytes(&record) + at, length))
            return -14;
        at += length;
    }
    size_t control_length = message_call ? control_out(task, message, socket, record, flags) : 0;
    if (message.name) {
        uint32_t capacity = min(message.name_length, uint32_t(128));
        uint64_t length_pointer = call.rsi + offsetof(Message, name_length);
        if (!message_call) {
            length_pointer = call.r9;
            if (!task.memory->space.copy_in(&capacity, length_pointer, 4))
                return -14;
            if (int32_t(capacity) < 0)
                return -22;
        }
        uint32_t actual = sizeof(Inet6Address);
        // The Linux receive wrapper stores the full length before address bytes.
        if (!task.memory->space.copy_out(length_pointer, &actual, 4) ||
            !copy_bytes(task, message.name, &record.destination, min(capacity, actual)))
            return -14;
    }
    if (message_call &&
        (!task.memory->space.copy_out(call.rsi + offsetof(Message, flags), &flags, 4) ||
         !task.memory->space.copy_out(call.rsi + offsetof(Message, control_length), &control_length,
                                      8)))
        return -14;
    // MSG_TRUNC and MSG_PEEK do not change error-queue dequeue/return semantics.
    return copied;
}
} // namespace ax
