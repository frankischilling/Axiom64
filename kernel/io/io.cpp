// SPDX-License-Identifier: GPL-3.0-or-later
#include "io/io.hpp"
#include "io/vectors.hpp"
#include "core/time.hpp"
#include "drivers/platform/devices.hpp"
#include "fs/file_lock.hpp"
#include "fs/record_lock.hpp"
#include "fs/descriptor.hpp"
#include "ipc/ipc.hpp"
#include "process/signals.hpp"
#include "net/packet.hpp"
#include "net/inet.hpp"
#include "net/inet6.hpp"
#include "net/netlink.hpp"
#include "net/tcp/socket.hpp"
#include "security/credentials.hpp"

namespace ax {
using Iovec = IoVector;

struct Message {
    uint64_t name;
    uint32_t name_length, padding;
    uint64_t iov, iov_count, control, control_length;
    uint32_t flags, padding2;
};

static_assert(sizeof(Iovec) == 16 && sizeof(Message) == 56);

struct IoRequest {
    Handle* handle;
    Task* record_task = nullptr;
    unsigned record_command = 0;
    RecordFlock record{}, original_record{};
    FileTable* reserved_table = nullptr;
    int reserved_fd = -1;
    Frame call;
    Iovec single, *vectors;
    size_t count;
    size_t cursor, cursor_offset, progress;
    unsigned flags;
    bool write, socket, accept, positioned, locking, connect, started;
    bool timed, stream_blocking;
    int connect_error;
    uint64_t deadline;
    uint64_t inet_generation;
    PacketAddress destination;
    unsigned destination_index;
    InetAddress inet_destination;
    Inet6Address inet6_destination;
    Inet6SendControl inet6_output;
    uint8_t* inet6_control_data;
    bool inet_destination_named;
    NetlinkAddress netlink_destination;
    uint8_t* packet_data;
    size_t packet_length;
    uint64_t address_pointer, address_length_pointer;
    uint64_t control_pointer, control_capacity;
    uint32_t address_capacity;
    uint64_t event_value;
    bool event_value_ready;
};

static void destroy(IoRequest* request) {
    if (!request)
        return;
    if (request->reserved_table)
        discard_reserved_fd(*request->reserved_table, request->reserved_fd);
    if (request->record_task)
        record_lock_discard(*request->record_task);
    if (request->vectors != &request->single)
        release(request->vectors);
    release(request->packet_data);
    release(request->inet6_control_data);
    close_handle(request->handle);
    release(request);
}

void io_discard(Task& task) {
    auto request = task.io;
    task.io = nullptr;
    destroy(request);
}

bool io_restartable(const Task& task) {
    return !task.io || (!task.io->timed && !task.io->progress);
}

int64_t io_interrupted_result(const Task& task) {
    return task.io && task.io->progress ? int64_t(task.io->progress) : -4;
}

static void capture_timeout(IoRequest& request) {
    auto h = request.handle;
    if (request.locking || (!h->socket && !h->inet && !h->inet6 && !h->packet && !h->netlink))
        return;
    auto timeout = request.write ? h->send_timeout : h->receive_timeout;
    if (!timeout.finite)
        return;
    clock_refresh();
    request.timed = true;
    request.deadline = timeout.ticks > UINT64_MAX - ticks ? UINT64_MAX : ticks + timeout.ticks;
}

static bool timeout_expired(const IoRequest& request) {
    if (!request.timed)
        return false;
    clock_refresh();
    return ticks >= request.deadline;
}

static int64_t timeout_result(const IoRequest& request) {
    return request.progress  ? int64_t(request.progress)
           : request.connect ? request.connect_error
                             : -11;
}

static int import_vectors(Task& task, IoRequest& request, uint64_t pointer, size_t count) {
    if (count > 1024)
        return request.call.rax == 46 || request.call.rax == 47 ? -90 : -22;
    request.count = count;
    if (!count)
        return 0;
    request.vectors = static_cast<Iovec*>(alloc(count * sizeof(Iovec)));
    if (!request.vectors)
        return -12;
    if (!task.memory->space.copy_in(request.vectors, pointer, count * sizeof(Iovec)))
        return -14;
    // Linux limits each operation to MAX_RW_COUNT, including vector operations.
    int64_t capacity = bound_io_vectors(request.vectors, count);
    return capacity < 0 ? int(capacity) : 0;
}

static int copy_packet(Task& task, IoRequest& request, size_t begin, size_t length,
                       uint8_t* output = nullptr) {
    if (!output)
        output = request.packet_data;
    size_t at = 0, end = begin + length;
    for (size_t i = 0; i < request.count && at < end; i++) {
        const auto& vector = request.vectors[i];
        size_t next = at + vector.length;
        if (next > begin) {
            size_t skip = begin > at ? begin - at : 0;
            size_t copied = min(vector.length - skip, end - at - skip);
            if (copied &&
                (vector.base > UINT64_MAX - skip ||
                 !task.memory->space.copy_in(output + at + skip, vector.base + skip, copied)))
                return -14;
        }
        at = next;
    }
    return 0;
}

static int prepare_packet(Task& task, IoRequest& request) {
    const auto& f = request.call;
    if (request.handle->inet && !inet_payload(request.handle->inet))
        return -95;
    if (request.accept)
        return -95;
    if (request.positioned)
        return -29;
    if (request.flags & ~unsigned(request.write ? 0x4040 : 2 | 0x20 | 0x40))
        return -95;
    if (request.write && request.handle->packet)
        request.destination_index = packet_interface(request.handle->packet);
    if (request.write && request.handle->inet)
        request.inet_destination = inet_peer(request.handle->inet);
    if (request.write && request.handle->inet6)
        request.inet6_destination = inet6_peer(request.handle->inet6);
    uint64_t address = f.rax == 44 ? f.r8 : 0;
    uint64_t address_length = f.rax == 44 ? f.r9 : 0;
    uint64_t control_pointer = 0, control_length = 0;
    if (f.rax == 19 || f.rax == 20) {
        int error = import_vectors(task, request, f.rsi, f.rdx);
        if (error)
            return error;
    } else if (f.rax == 46 || f.rax == 47) {
        Message message;
        if (!task.memory->space.copy_in(&message, f.rsi, sizeof(message)))
            return -14;
        if ((request.handle->inet6 || (!request.write && request.handle->inet)) && message.name) {
            if (int32_t(message.name_length) < 0)
                return -22;
            message.name_length = min(message.name_length, uint32_t(128));
            if (request.write && !message.name_length)
                message.name = 0;
        }
        if (request.write && message.control_length) {
            if (!request.handle->inet6)
                return -95;
            control_pointer = message.control;
            control_length = message.control_length;
        }
        if (request.write) {
            address = message.name;
            address_length = message.name_length;
        } else {
            request.address_pointer = message.name;
            request.address_capacity = message.name_length;
            request.control_pointer = message.control;
            request.control_capacity = message.control_length;
        }
        int error = import_vectors(task, request, message.iov, message.iov_count);
        if (error)
            return error;
    } else {
        request.single = {f.rsi, min(f.rdx, uint64_t(0x7ffff000))};
        request.vectors = &request.single;
        request.count = 1;
    }
    for (size_t i = 0; i < request.count; i++) {
        const auto& vector = request.vectors[i];
        if (vector.base >= user_limit || vector.length > user_limit - vector.base)
            return -14;
    }
    if (request.write && address) {
        if (request.handle->netlink) {
            if (address_length < sizeof(NetlinkAddress))
                return -22;
            if (!task.memory->space.copy_in(&request.netlink_destination, address,
                                            sizeof(NetlinkAddress)))
                return -14;
        } else if (request.handle->inet6) {
            uint32_t length = address_length;
            if (length > 128)
                return -22;
            uint8_t bytes[128];
            if (length && !task.memory->space.copy_in(bytes, address, length))
                return -14;
            request.inet6_destination = {};
            memcpy(&request.inet6_destination, bytes, min(size_t(length), sizeof(Inet6Address)));
            if (length < sizeof(Inet6Address))
                request.inet6_destination.scope = 0;
        } else if (request.handle->inet) {
            if (address_length < sizeof(InetAddress))
                return -22;
            if (!task.memory->space.copy_in(&request.inet_destination, address,
                                            sizeof(InetAddress)))
                return -14;
        } else {
            if (address_length < sizeof(PacketAddress))
                return -22;
            if (!task.memory->space.copy_in(&request.destination, address, sizeof(PacketAddress)))
                return -14;
            if (request.destination.family != 17 || request.destination.length > 8)
                return -22;
            request.destination_index = request.destination.index;
        }
    }
    if (f.rax == 45 && f.r8) {
        request.address_pointer = f.r8;
        request.address_length_pointer = f.r9;
        if (!request.handle->inet6 && !request.handle->inet &&
            !task.memory->space.copy_in(&request.address_capacity, f.r9, 4))
            return -14;
    }
    if (request.write && request.handle->inet6) {
        // Import the complete control buffer after vectors and address bytes,
        // before protocol-specific destination and control validation.
        if (int error = inet6_capture_control(task, control_pointer, control_length,
                                              request.inet6_control_data))
            return error;
    }
    for (size_t i = 0; i < request.count; i++)
        request.packet_length += request.vectors[i].length;
    if (!request.write)
        return 0;
    if (request.handle->netlink) {
        if (int error = netlink_target(request.netlink_destination))
            return error;
        if (request.packet_length > netlink_max_request)
            return -90;
    } else if (request.handle->inet6) {
        request.inet_destination_named = address != 0;
        int error = inet6_target(request.handle->inet6, request.inet6_destination,
                                 request.inet_destination_named, uint32_t(address_length));
        if (error)
            return error;
    } else if (request.handle->inet) {
        request.inet_destination_named = address != 0;
        int error = inet_target(request.handle->inet, request.inet_destination,
                                request.inet_destination_named);
        if (error)
            return error;
        if (request.packet_length > 65535 - 20)
            return -90;
    } else {
        if (!request.destination_index || !net_info(request.destination_index))
            return -6;
        if (request.packet_length > max_ethernet_frame)
            return -90;
        if (request.packet_length < ethernet_header)
            return -22;
    }
    if (request.handle->inet6) {
        int error = inet6_parse_send_control(
            request.handle->inet6, request.inet6_destination, request.inet6_control_data,
            control_length, request.inet6_output, capable(task.credentials, Capability::net_raw));
        if (error)
            return error;
        // Sticky views can change through another alias while output waits.
        // Keep only immutable selected bytes through request teardown.
        if (int error = inet6_own_send_extensions(request.inet6_output, request.inet6_control_data))
            return error;
    }
    size_t prefix = request.handle->inet6 ? inet6_send_prefix(request.handle->inet6) : 0;
    if (request.packet_length < prefix)
        return -14;
    uint8_t protocol_bytes[2];
    if (prefix) {
        // Import raw protocol bytes before routing and length admission.
        if (int error = copy_packet(task, request, 0, prefix, protocol_bytes))
            return error;
    }
    if (request.handle->inet6) {
        if (int error = inet6_send_admit(request.handle->inet6, request.inet6_destination,
                                         request.packet_length, prefix ? protocol_bytes : nullptr,
                                         request.inet_destination_named, &request.inet6_output))
            return error;
    }
    if (request.packet_length) {
        request.packet_data = static_cast<uint8_t*>(alloc(request.packet_length));
        if (!request.packet_data)
            return -12;
    }
    if (prefix) {
        memcpy(request.packet_data, protocol_bytes, prefix);
    }
    return copy_packet(task, request, prefix, request.packet_length - prefix);
}

static int prepare(Task& task, IoRequest& request) {
    const auto& f = request.call;
    if (f.rax == 72) {
        request.locking = true;
        request.record_task = &task;
        request.record_command = unsigned(f.rsi);
        if (request.handle->flags & 010000000)
            return -9;
        if (!task.memory->space.copy_in(&request.record, f.rdx, sizeof(RecordFlock)))
            return -14;
        request.original_record = request.record;
        return record_lock_prepare(request.handle, request.record_command, request.record);
    }
    if (f.rax == 73) {
        request.locking = true;
        return 0;
    }
    if (f.rax == 42 && inet_stream(request.handle->inet)) {
        request.connect = request.write = true;
        if (tcp_ipv6(request.handle->inet))
            return tcp6_import(task, f.rsi, uint32_t(f.rdx), request.inet6_destination, true);
        if (f.rdx < sizeof(uint16_t))
            return -22;
        request.inet_destination = {};
        if (!task.memory->space.copy_in(&request.inet_destination.family, f.rsi, sizeof(uint16_t)))
            return -14;
        // AF_UNSPEC disconnect imports only the family, including a two-byte address.
        if (request.inet_destination.family) {
            if (f.rdx < sizeof(InetAddress))
                return -22;
            if (!task.memory->space.copy_in(&request.inet_destination, f.rsi, sizeof(InetAddress)))
                return -14;
        }
        return 0;
    }
    if (request.handle->socket && request.handle->socket->type != 1)
        return -95;
    request.write = f.rax == 1 || f.rax == 18 || f.rax == 20 || f.rax == 44 || f.rax == 46;
    request.socket = f.rax == 44 || f.rax == 45 || f.rax == 46 || f.rax == 47;
    request.accept = f.rax == 43 || f.rax == 288;
    request.positioned = f.rax == 17 || f.rax == 18;
    if ((request.socket || request.accept) && !request.handle->socket && !request.handle->packet &&
        !request.handle->inet && !request.handle->inet6 && !request.handle->netlink)
        return -88;
    if (!request.socket && !request.accept &&
        ((request.handle->flags & 3) == (request.write ? 0u : 1u)))
        return -9;
    if (request.socket)
        request.flags = f.rax == 46 || f.rax == 47 ? f.rdx : f.r10;
    if (request.handle->packet || (request.handle->inet && !inet_stream(request.handle->inet)) ||
        request.handle->inet6 || request.handle->netlink)
        return prepare_packet(task, request);
    if (request.accept) {
        if (f.rax == 288 && (f.r10 & ~uint64_t(0x80800)))
            return -22;
        request.reserved_fd = reserve_fd(task, 0, f.rax == 288 && (f.r10 & 0x80000));
        if (request.reserved_fd < 0)
            return request.reserved_fd;
        request.reserved_table = task.files;
        return 0;
    }
    if (request.positioned) {
        if (request.handle->pipe || request.handle->event || request.handle->socket ||
            inet_stream(request.handle->inet) ||
            (request.handle->node && (request.handle->node->mode & 0170000) == character))
            return -29;
        if (int64_t(f.r10) < 0)
            return -22;
    }
    if (request.socket) {
        request.flags = f.rax == 46 || f.rax == 47 ? f.rdx : f.r10;
        unsigned allowed = 2 | 0x40 | 0x4000;
        if (inet_stream(request.handle->inet))
            allowed |= 0x100;
        if (request.flags & ~allowed)
            return -95;
        if (f.rax == 44 && f.r8)
            return -106;
    }
    if (f.rax == 19 || f.rax == 20)
        return import_vectors(task, request, f.rsi, f.rdx);
    if (f.rax == 46 || f.rax == 47) {
        Message message;
        if (!task.memory->space.copy_in(&message, f.rsi, sizeof(message)))
            return -14;
        if (message.name && !(f.rax == 47 && inet_stream(request.handle->inet)))
            return -95;
        if (message.control_length && f.rax == 46)
            return -95;
        return import_vectors(task, request, message.iov, message.iov_count);
    }
    request.single = {f.rsi, min(f.rdx, uint64_t(0x7ffff000))};
    request.vectors = &request.single;
    request.count = 1;
    return 0;
}

static int64_t stream_transfer(Task& task, IoRequest& request, const Iovec& vector,
                               size_t peek_offset) {
    if (vector.base >= user_limit || vector.length > user_limit - vector.base)
        return -14;
    auto socket = request.handle->inet;
    uint8_t buffer[4096];
    size_t done = 0;
    while (done < vector.length) {
        uint64_t address = vector.base + done;
        size_t count = min(size_t(vector.length - done),
                           min(sizeof(buffer), size_t(page_size - address % page_size)));
        int64_t result;
        if (request.write) {
            result = tcp_write_check(socket);
            if (!result) {
                if (!task.memory->space.copy_in(buffer, address, count))
                    return done ? int64_t(done) : -14;
                result = tcp_write(socket, buffer, count, false);
            }
        } else {
            bool peek = request.flags & 2;
            result = tcp_read(socket, buffer, count, true, peek ? peek_offset + done : 0);
            if (result > 0) {
                if (!task.memory->space.copy_out(address, buffer, result))
                    return done ? int64_t(done) : -14;
                // The current single-CPU I/O path cannot change this queue during the copy.
                if (!peek && tcp_read(socket, buffer, result, false) != result)
                    panic("TCP receive changed during copy");
            }
        }
        if (result < 0) {
            if (result == -32 && request.write && !done && !request.progress &&
                !(request.socket && (request.flags & 0x4000)))
                queue_signal(&task, 13, task.process->pid);
            return done ? int64_t(done) : result;
        }
        done += result;
        if (size_t(result) < count)
            break;
    }
    return done;
}

struct VectorCursor {
    IoRequest& request;
    size_t index = 0, offset = 0;

    bool copy(Task& task, uint8_t* buffer, size_t length) {
        while (length) {
            while (index < request.count && offset == request.vectors[index].length) {
                index++;
                offset = 0;
            }
            if (index == request.count)
                panic("I/O cursor exceeds captured vectors");
            const auto& vector = request.vectors[index];
            uint64_t address = vector.base + offset;
            size_t count = min(length, min(size_t(vector.length - offset),
                                           size_t(page_size - address % page_size)));
            bool copied = request.write ? task.memory->space.copy_in(buffer, address, count)
                                        : task.memory->space.copy_out(address, buffer, count);
            if (!copied)
                return false;
            offset += count;
            buffer += count;
            length -= count;
        }
        return true;
    }
};

static int64_t control_attempt(Task& task, IoRequest& request, const ControlFileOps& control) {
    auto handle = request.handle;
    size_t length = 0;
    for (size_t n = 0; n < request.count; n++) {
        const auto& vector = request.vectors[n];
        if (vector.base > user_limit || vector.length > user_limit - vector.base)
            return -14;
        length += vector.length;
    }
    // Linux vector I/O returns before the filesystem for an empty iterator.
    if (!length && (request.call.rax == 19 || request.call.rax == 20))
        return 0;
    if (int error = node_validate(handle->node))
        return error;
    if (request.write && node_readonly(handle->node))
        return -30;
    if (control.access(handle->node, request.write ? 2 : 4, false))
        return -1;
    auto buffer = static_cast<uint8_t*>(alloc(length + 1));
    if (!buffer)
        return -12;
    VectorCursor cursor{request};
    // Copy every input page before invoking a state-changing handler. A late
    // vector or page fault must not commit a valid prefix of a sysctl write.
    if (request.write && !cursor.copy(task, buffer, length)) {
        release(buffer);
        return -14;
    }
    buffer[length] = 0;
    uint64_t offset = handle->offset;
    int64_t result =
        request.write ? write_handle(handle, buffer, length) : read_handle(handle, buffer, length);
    if (result > int64_t(length))
        panic("control file exceeds captured operation");
    if (result > 0 && !request.write && !cursor.copy(task, buffer, size_t(result)))
        result = -14;
    if (result < 0)
        handle->offset = offset;
    release(buffer);
    return result;
}

static int64_t local_stream_attempt(Task& task, IoRequest& request) {
    auto handle = request.handle;
    size_t remaining = 0;
    for (size_t n = 0; n < request.count; n++) {
        const auto& vector = request.vectors[n];
        if (vector.length &&
            (vector.base >= user_limit || vector.length > user_limit - vector.base))
            return -14;
        remaining += vector.length;
    }
    VectorCursor cursor{request};
    uint8_t buffer[4096];
    size_t done = 0;
    bool peek = request.flags & 2;
    while (remaining) {
        size_t count = min(remaining, sizeof(buffer));
        int64_t result;
        if (request.write) {
            result = handle->socket          ? socket_write(handle->socket, nullptr, 0)
                     : handle->pipe->readers ? 0
                                             : -32;
            if (!result) {
                size_t capacity = handle->socket
                                      ? handle->socket->peer->capacity - handle->socket->peer->size
                                      : sizeof(Pipe::bytes) - handle->pipe->size;
                // Small pipe writes wait for the entire request to fit.
                if (!capacity ||
                    (handle->pipe && !done && remaining <= sizeof(buffer) && capacity < remaining))
                    return done ? int64_t(done) : -11;
                count = min(count, capacity);
                if (!cursor.copy(task, buffer, count))
                    return done ? int64_t(done) : -14;
                result = handle->socket ? socket_write(handle->socket, buffer, count)
                                        : write_handle(handle, buffer, count);
            }
        } else {
            result = handle->socket
                         ? socket_read(handle->socket, buffer, count, true, peek ? done : 0)
                         : pipe_read(handle->pipe, buffer, count, true);
            if (result > 0) {
                // Stream copies commit only after their complete returned
                // chunk reaches userspace, including across vector boundaries.
                if (!cursor.copy(task, buffer, result))
                    return done ? int64_t(done) : -14;
                // Syscalls run with interrupts masked on the current single CPU.
                int64_t consumed = handle->socket
                                       ? peek ? result : socket_read(handle->socket, buffer, result)
                                       : pipe_read(handle->pipe, buffer, result);
                if (consumed != result)
                    panic("local stream changed during copy");
            }
        }
        if (result < 0) {
            if (result == -32 && request.write && !(request.socket && (request.flags & 0x4000)))
                queue_signal(&task, 13, task.process->pid);
            return done ? int64_t(done) : result;
        }
        done += result;
        remaining -= result;
        if (size_t(result) < count)
            break;
    }
    return done;
}

static int64_t transfer(Task& task, IoRequest& request, const Iovec& vector, size_t peek_offset) {
    auto h = request.handle;
    if (inet_stream(h->inet))
        return stream_transfer(task, request, vector, peek_offset);
    if (vector.base >= user_limit || vector.length > user_limit - vector.base)
        return -14;
    if (device_ignores_buffer(h, request.write))
        return request.write ? write_handle(h, nullptr, vector.length)
                             : read_handle(h, nullptr, vector.length);
    uint8_t buffer[4096];
    size_t done = 0;
    while (done < vector.length) {
        uint64_t address = vector.base + done;
        size_t count = min(size_t(vector.length - done), sizeof(buffer));
        bool regular = h->node && (h->node->mode & 0170000) == regular_file;
        // File copies commit a page prefix.
        if (regular)
            count = min(count, size_t(page_size - address % page_size));
        if (request.write && !task.memory->space.copy_in(buffer, address, count))
            return done ? int64_t(done) : -14;
        uint64_t old_offset = h->offset;
        // Devices without a non-consuming read must validate this chunk
        // before changing their queues or hardware state.
        if (!request.write && !regular && !task.memory->space.valid(address, count, true))
            return done ? int64_t(done) : -14;
        int64_t n = request.write ? write_handle(h, buffer, count) : read_handle(h, buffer, count);
        if (n < 0) {
            if (n == -32 && request.write && !(request.socket && (request.flags & 0x4000)))
                queue_signal(&task, 13, task.process->pid);
            return done ? int64_t(done) : n;
        }
        if (!request.write && n) {
            size_t copied = 0;
            while (copied < size_t(n)) {
                size_t length =
                    min(size_t(n) - copied, size_t(page_size - (address + copied) % page_size));
                if (!task.memory->space.copy_out(address + copied, buffer + copied, length)) {
                    if (regular)
                        h->offset = old_offset;
                    return done ? int64_t(done) : -14;
                }
                copied += length;
            }
        }
        done += n;
        if (size_t(n) < count || (!request.write && !request.socket && h->node &&
                                  (h->node->mode & 0170000) == character))
            break;
    }
    return done;
}

static bool copy_packet_output(Task& task, uint64_t destination, const void* data, size_t length) {
    if (!length)
        return true;
    if (destination >= user_limit || length > user_limit - destination)
        return false;
    auto source = static_cast<const uint8_t*>(data);
    while (length) {
        // Preserve bytes on writable pages before a later output-copy fault.
        size_t count = min(length, size_t(page_size - destination % page_size));
        if (!task.memory->space.copy_out(destination, source, count))
            return false;
        destination += count;
        source += count;
        length -= count;
    }
    return true;
}

static int64_t packet_attempt(Task& task, IoRequest& request) {
    net_poll();
    const auto& f = request.call;
    if (request.write) {
        if (request.handle->netlink)
            return netlink_send(request.handle->netlink, task.process->pid, request.packet_data,
                                request.packet_length);
        if (request.handle->inet)
            return inet_send(request.handle->inet, request.inet_destination, request.packet_data,
                             request.packet_length, request.inet_destination_named);
        if (request.handle->inet6)
            return inet6_send(request.handle->inet6, request.inet6_destination, request.packet_data,
                              request.packet_length, request.inet_destination_named,
                              &request.inet6_output);
        int result = net_send(request.destination_index, request.packet_data, request.packet_length,
                              request.handle->packet);
        return result ? result : int64_t(request.packet_length);
    }
    if (!request.socket && !request.packet_length)
        return 0;
    if (request.handle->inet)
        if (int error = inet_error(request.handle->inet, true))
            return -error;
    if (request.handle->inet6)
        if (int error = inet6_error(request.handle->inet6, true))
            return -error;
    auto frame = request.handle->packet ? packet_front(request.handle->packet) : nullptr;
    auto ip = request.handle->inet ? inet_front(request.handle->inet) : nullptr;
    auto ip6 = request.handle->inet6 ? inet6_front(request.handle->inet6) : nullptr;
    auto nl = request.handle->netlink ? netlink_front(request.handle->netlink) : nullptr;
    if (!frame && !ip && !ip6 && !nl) {
        if (request.handle->netlink)
            return -11;
        if (request.handle->inet6) {
            int error = inet6_error(request.handle->inet6, true);
            bool blocking = !(request.handle->flags & 04000) && !(request.flags & 0x40);
            return error                                                     ? -error
                   : blocking && (inet6_shutdown(request.handle->inet6) & 1) ? 0
                                                                             : -11;
        }
        if (request.handle->inet) {
            int error = inet_error(request.handle->inet, true);
            bool blocking = !(request.handle->flags & 04000) && !(request.flags & 0x40);
            return error ? -error : blocking && (inet_shutdown(request.handle->inet) & 1) ? 0 : -11;
        }
        auto info = net_info(packet_interface(request.handle->packet));
        return info && !info->live ? -5 : -11;
    }
    size_t length = nl ? nl->length : ip ? ip->length : ip6 ? ip6->length : frame->length;
    const auto bytes = nl    ? netlink_bytes(nl)
                       : ip  ? inet_bytes(ip)
                       : ip6 ? inet6_bytes(ip6)
                             : packet_bytes(frame);
    const void* source = nl    ? static_cast<const void*>(&nl->source)
                         : ip  ? static_cast<const void*>(&ip->source)
                         : ip6 ? static_cast<const void*>(&ip6->source)
                               : &frame->source;
    const auto copy_fault = [&request](int error = -14) -> int64_t {
        // Linux raw Internet receives dequeue even when a non-peek copy faults.
        if (request.handle->inet && !(request.flags & 2))
            inet_consume(request.handle->inet);
        if (request.handle->inet6 && !(request.flags & 2))
            inet6_consume(request.handle->inet6);
        if (request.handle->netlink && !(request.flags & 2))
            netlink_consume(request.handle->netlink);
        return error;
    };
    size_t remaining = min(length, request.packet_length), at = 0;
    for (size_t i = 0; i < request.count && remaining; i++) {
        const auto& vector = request.vectors[i];
        size_t count = min(remaining, size_t(vector.length));
        if (count && !copy_packet_output(task, vector.base, bytes + at, count))
            return copy_fault();
        at += count;
        remaining -= count;
    }
    if (frame)
        packet_observed(request.handle->packet, *frame);
    uint32_t actual_address = nl    ? sizeof(NetlinkAddress)
                              : ip  ? sizeof(InetAddress)
                              : ip6 ? sizeof(Inet6Address)
                                    : sizeof(PacketAddress);
    if ((ip || ip6) && f.rax == 45 && request.address_pointer) {
        if (!task.memory->space.copy_in(&request.address_capacity, request.address_length_pointer,
                                        4))
            return copy_fault();
        if (int32_t(request.address_capacity) < 0)
            return copy_fault(-22);
    }
    uint32_t message_flags = length > request.packet_length ? 0x20 : 0;
    uint64_t control_length = 0;
    if (f.rax == 47) {
        if (ip)
            control_length =
                inet_receive_control(task, request.handle->inet, *ip, request.control_pointer,
                                     request.control_capacity, message_flags);
        else if (ip6)
            control_length =
                inet6_receive_control(task, request.handle->inet6, *ip6, request.control_pointer,
                                      request.control_capacity, message_flags);
    }
    if ((ip || ip6) && request.address_pointer) {
        // Linux stores the full source length before copying any address bytes.
        uint64_t length_pointer =
            f.rax == 47 ? f.rsi + offsetof(Message, name_length) : request.address_length_pointer;
        if (!task.memory->space.copy_out(length_pointer, &actual_address, 4))
            return copy_fault();
    }
    if (request.address_pointer &&
        (!copy_packet_output(task, request.address_pointer, source,
                             min(request.address_capacity, actual_address)) ||
         (!ip && !ip6 && request.address_length_pointer &&
          !task.memory->space.copy_out(request.address_length_pointer, &actual_address, 4))))
        return copy_fault();
    if (f.rax == 47) {
        uint32_t address_length = request.address_pointer ? actual_address : 0;
        // A NULL Internet source-name pointer leaves the caller's length untouched.
        if ((!ip && !ip6 &&
             !task.memory->space.copy_out(f.rsi + offsetof(Message, name_length), &address_length,
                                          4)) ||
            !task.memory->space.copy_out(f.rsi + offsetof(Message, flags), &message_flags, 4) ||
            !task.memory->space.copy_out(f.rsi + offsetof(Message, control_length), &control_length,
                                         8))
            return copy_fault();
    }
    int64_t result = request.flags & 0x20 ? length : at;
    if (!(request.flags & 2)) {
        if (request.handle->netlink)
            netlink_consume(request.handle->netlink);
        else if (request.handle->inet)
            inet_consume(request.handle->inet);
        else if (request.handle->inet6)
            inet6_consume(request.handle->inet6);
        else
            packet_consume(request.handle->packet);
    }
    return result;
}

static int64_t stream_attempt(Task& task, IoRequest& request) {
    net_poll();

    // A write call queues its copied prefix before flushing, including vectors
    // and page-sized copies. Every exit flushes that prefix, even after a fault
    // or a retained wait; no user pointer enters the transport queue.
    struct Flush {
        bool write;

        ~Flush() {
            if (write)
                tcp_poll();
        }
    } flush{request.write};

    while (request.cursor < request.count) {
        const auto& original = request.vectors[request.cursor];
        Iovec vector{original.base + request.cursor_offset,
                     original.length - request.cursor_offset};
        if (!vector.length) {
            request.cursor++;
            request.cursor_offset = 0;
            continue;
        }
        int64_t count = transfer(task, request, vector, request.progress);
        if (count < 0) {
            if (count == -11 && request.stream_blocking)
                return would_block;
            return request.progress ? int64_t(request.progress) : count;
        }
        if (!count)
            return request.progress;
        request.progress += count;
        request.cursor_offset += count;
    }
    return request.progress;
}

static int64_t eventfd_attempt(Task& task, IoRequest& request) {
    size_t total = 0;
    for (size_t i = 0; i < request.count; i++) {
        const auto& vector = request.vectors[i];
        // access_ok precedes the counter operation, but mapped-page faults do not.
        if (vector.base >= user_limit || vector.length > user_limit - vector.base)
            return -14;
        total += vector.length;
    }
    if (!total && (request.call.rax == 19 || request.call.rax == 20))
        return 0;
    if (!request.write) {
        if (total < sizeof(uint64_t))
            return -22;
        uint64_t value;
        int64_t result = read_handle(request.handle, &value, sizeof(value));
        if (result < 0)
            return result == -11 && request.stream_blocking ? would_block : result;
        // Linux consumes the counter before copying, including a late readv fault.
        size_t copied = 0;
        for (size_t i = 0; i < request.count && copied < sizeof(value); i++) {
            const auto& vector = request.vectors[i];
            size_t length = min(size_t(vector.length), sizeof(value) - copied);
            size_t offset = 0;
            while (offset < length) {
                uint64_t address = vector.base + offset;
                size_t count = min(length - offset, size_t(page_size - address % page_size));
                if (!task.memory->space.copy_out(
                        address, reinterpret_cast<uint8_t*>(&value) + copied, count))
                    return -14;
                copied += count;
                offset += count;
            }
        }
        return sizeof(value);
    }
    if (!total)
        return -22;
    while (request.cursor < request.count) {
        const auto& vector = request.vectors[request.cursor];
        if (!vector.length) {
            request.cursor++;
            continue;
        }
        if (!request.event_value_ready) {
            // writev retains the scalar boundary of every nonempty vector.
            if (vector.length != sizeof(uint64_t))
                return request.progress ? int64_t(request.progress) : -22;
            if (!task.memory->space.copy_in(&request.event_value, vector.base,
                                            sizeof(request.event_value)))
                return request.progress ? int64_t(request.progress) : -14;
            request.event_value_ready = true;
        }
        int64_t result =
            write_handle(request.handle, &request.event_value, sizeof(request.event_value));
        if (result < 0) {
            if (result == -11 && request.stream_blocking)
                return would_block;
            return request.progress ? int64_t(request.progress) : result;
        }
        request.progress += result;
        request.cursor++;
        request.event_value_ready = false;
    }
    return request.progress;
}

static int64_t attempt(Task& task, IoRequest& request) {
    auto h = request.handle;
    const auto& f = request.call;
    // A disconnected stream may already have a successor on this description.
    // Preserve the old call's prefix without touching the successor or its error.
    if (inet_stream(h->inet) && !request.accept &&
        request.inet_generation != tcp_generation(h->inet)) {
        if (request.progress)
            return int64_t(request.progress);
        bool sending = request.write && !request.connect;
        int error = sending ? tcp_cancelled_write_error(h->inet) : 32;
        if (error == 32 && sending && !(request.socket && (request.flags & 0x4000)))
            queue_signal(&task, 13, task.process->pid);
        return -error;
    }
    if (h->event && !request.locking)
        return eventfd_attempt(task, request);
    if (request.connect) {
        net_poll();
        if (!request.started) {
            request.started = true;
            int result = tcp_ipv6(h->inet) ? tcp6_connect(h->inet, request.inet6_destination)
                                           : tcp_connect(h->inet, request.inet_destination);
            if ((result != -115 && result != -114) || !request.stream_blocking)
                return result;
            request.connect_error = result;
        }
        return tcp_connect_result(h->inet);
    }
    if (request.locking) {
        if (request.record_command) {
            int result = record_lock_try(task, h, request.record_command, request.record);
            if (!result && (request.record_command == 5 || request.record_command == 36)) {
                if (request.record.type == 2) {
                    request.original_record.type = 2;
                    request.record = request.original_record;
                }
                return task.memory->space.copy_out(f.rdx, &request.record, sizeof(RecordFlock))
                           ? 0
                           : -14;
            }
            if (!result && request.record_command < 36) {
                int fd = int(f.rdi);
                if (fd < 0 || unsigned(fd) >= max_fds || task.files->entries[fd].handle != h) {
                    record_lock_close(*task.files, h->node);
                    return -9;
                }
            }
            return result == -11 && (request.record_command == 7 || request.record_command == 38)
                       ? would_block
                       : result;
        }
        int result = file_lock_try(h, uint32_t(f.rsi));
        return result == -11 && !(f.rsi & 4) ? would_block : result;
    }
    if (h->packet || (h->inet && !inet_stream(h->inet)) || h->inet6 || h->netlink) {
        int64_t result = packet_attempt(task, request);
        if (result == -11 && !(h->flags & 04000) && !(request.flags & 0x40))
            return would_block;
        return result;
    }
    if (request.accept)
        return inet_stream(h->inet) ? tcp_accept(task, h, f.rsi, f.rdx, f.rax == 288 ? f.r10 : 0,
                                                 request.reserved_fd)
                                    : socket_accept(task, h, f.rsi, f.rdx, f.rax == 288 ? f.r10 : 0,
                                                    request.reserved_fd);
    size_t done = 0;
    int64_t result = 0;
    uint64_t old_offset = h->offset;
    auto control = node_control(h->node);
    // Scalar empty reads reach device readiness; empty readv requests keep their shortcut.
    if (f.rax == 0 && !request.single.length && !control)
        result = f.rsi >= user_limit ? -14 : read_handle(h, nullptr, 0);
    if (request.positioned)
        h->offset = f.r10;
    bool completion =
        inet_stream(h->inet) &&
        (request.write ? request.stream_blocking : request.socket && (request.flags & 0x100));
    bool empty_send = false;
    if (request.socket && request.write) {
        bool empty = true;
        for (size_t i = 0; i < request.count; i++)
            empty &= request.vectors[i].length == 0;
        if (empty) {
            empty_send = true;
            result = inet_stream(h->inet) ? tcp_write(h->inet, nullptr, 0)
                                          : socket_write(h->socket, nullptr, 0);
            if (result == -32 && !(request.flags & 0x4000))
                queue_signal(&task, 13, task.process->pid);
            completion = true;
        }
    }
    if (completion && !empty_send)
        result = stream_attempt(task, request);
    if (!completion && (h->socket || h->pipe)) {
        if (result >= 0)
            result = local_stream_attempt(task, request);
        completion = true;
    }
    if (!completion && control) {
        result = control_attempt(task, request, *control);
        completion = true;
    }
    bool limited_write =
        request.write && !control && h->node && (h->node->mode & 0170000) == regular_file;
    size_t budget = 0;
    if (limited_write) {
        for (size_t i = 0; i < request.count; i++) {
            const auto& vector = request.vectors[i];
            if (vector.length &&
                (vector.base >= user_limit || vector.length > user_limit - vector.base)) {
                result = -14;
                completion = true;
                break;
            }
            budget += vector.length;
        }
        if (!completion) {
            if (int error = write_handle_limit(h, budget)) {
                result = error;
                completion = true;
            }
        }
    }
    for (size_t i = 0; !completion && i < request.count && (!limited_write || done < budget); i++) {
        auto vector = request.vectors[i];
        if (limited_write)
            vector.length = min(vector.length, uint64_t(budget - done));
        if (!vector.length)
            continue;
        if (done && !handle_ready(h, request.write))
            break;
        int64_t n = transfer(task, request, vector, done);
        if (n < 0) {
            result = done ? int64_t(done) : n;
            break;
        }
        done += n;
        result = done;
        if (uint64_t(n) < vector.length)
            break;
    }
    if (request.positioned)
        h->offset = old_offset;
    // Regular-file errors are results, including procfs readiness errors. They
    // do not represent a stream operation to retain until a pollable event.
    bool regular_file = h->node && (h->node->mode & 0170000) == 0100000;
    if (result == -11 && !regular_file && !(h->flags & 04000) && !(request.flags & 0x40) &&
        !request.positioned)
        return would_block;
    if (result >= 0 && f.rax == 45 && f.r8) {
        uint32_t length = 0;
        int error = inet_stream(h->inet)
                        ? task.memory->space.copy_out(f.r9, &length, sizeof(length)) ? 0 : -14
                        : socket_output_address(task, h->socket->peer ? h->socket->peer : h->socket,
                                                f.r8, f.r9);
        if (error)
            return error;
    }
    if (result >= 0 && f.rax == 47) {
        uint64_t control_length = 0;
        uint32_t flags = 0;
        if (!task.memory->space.copy_out(f.rsi + offsetof(Message, control_length), &control_length,
                                         8) ||
            !task.memory->space.copy_out(f.rsi + offsetof(Message, flags), &flags, 4))
            return -14;
        if (inet_stream(h->inet)) {
            uint32_t length = 0;
            if (!task.memory->space.copy_out(f.rsi + offsetof(Message, name_length), &length, 4))
                return -14;
        }
    }
    return result;
}

int64_t io_syscall(Task& task, const Frame& frame) {
    // Linux validates the operation before looking up the descriptor.
    if (frame.rax == 73 && !file_lock_operation(uint32_t(frame.rsi)))
        return -22;
    int fd = int(frame.rdi);
    Handle* h = fd >= 0 && unsigned(fd) < max_fds ? task.files->entries[fd].handle : nullptr;
    if (!h || (h->flags & 010000000))
        return -9;
    if (task.io)
        panic("active I/O at syscall entry");
    unsigned flags = frame.rax == 47 ? frame.rdx : frame.r10;
    if (h->inet6 && (frame.rax == 45 || frame.rax == 47) && (flags & 0x2000)) {
        retain(h);
        int64_t result = inet6_receive_error(task, h->inet6, frame);
        close_handle(h);
        return result;
    }
    auto request = static_cast<IoRequest*>(alloc(sizeof(IoRequest)));
    if (!request)
        return -12;
    *request = {};
    request->handle = h;
    request->call = frame;
    retain(h);
    int error = prepare(task, *request);
    if (!error) {
        request->inet_generation = tcp_generation(h->inet);
        // Linux captures O_NONBLOCK for this call; an alias cannot alter a retained cursor.
        request->stream_blocking =
            (inet_stream(h->inet) || h->event) && !(h->flags & 04000) && !(request->flags & 0x40);
        capture_timeout(*request);
    }
    int64_t result = error ? error : attempt(task, *request);
    if (result == would_block && timeout_expired(*request))
        result = timeout_result(*request);
    if (result == would_block) {
        task.io = request;
        task.state = State::blocked;
        task.wait = request->locking ? Wait::file_lock : request->write ? Wait::write : Wait::read;
        task.wait_fd = fd;
    } else
        destroy(request);
    return result;
}

bool io_resume(Task& task) {
    auto request = task.io;
    if (!request)
        panic("blocked I/O without request");
    // An unavailable handle cannot make progress or access an expired wait's buffers.
    int64_t result = would_block;
    if (request->locking || request->handle->packet || request->handle->inet ||
        request->handle->netlink || handle_ready(request->handle, request->write) ||
        (request->handle->flags & 04000))
        result = attempt(task, *request);
    if (result == would_block) {
        if (!timeout_expired(*request))
            return false;
        result = timeout_result(*request);
    }
    // Commit the result before signal delivery; handlers have their own syscall state.
    task.frame.rip += 2;
    task.frame.rax = result;
    task.wait = Wait::none;
    task.state = State::runnable;
    io_discard(task);
    epoll_notify();
    return true;
}
} // namespace ax
