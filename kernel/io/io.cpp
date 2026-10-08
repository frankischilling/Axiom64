// SPDX-License-Identifier: GPL-3.0-or-later
#include "io/io.hpp"
#include "fs/file_lock.hpp"
#include "ipc/ipc.hpp"
#include "process/signals.hpp"
#include "net/packet.hpp"
#include "net/inet.hpp"
#include "net/netlink.hpp"

namespace ax {
struct Iovec {
    uint64_t base, length;
};

struct Message {
    uint64_t name;
    uint32_t name_length, padding;
    uint64_t iov, iov_count, control, control_length;
    uint32_t flags, padding2;
};

static_assert(sizeof(Iovec) == 16 && sizeof(Message) == 56);

struct IoRequest {
    Handle* handle;
    Frame call;
    Iovec single, *vectors;
    size_t count;
    unsigned flags;
    bool write, socket, accept, positioned, locking;
    PacketAddress destination;
    unsigned destination_index;
    InetAddress inet_destination;
    NetlinkAddress netlink_destination;
    uint8_t* packet_data;
    size_t packet_length;
    uint64_t address_pointer, address_length_pointer;
    uint32_t address_capacity;
};

static void destroy(IoRequest* request) {
    if (!request)
        return;
    if (request->vectors != &request->single)
        release(request->vectors);
    release(request->packet_data);
    close_handle(request->handle);
    release(request);
}

void io_discard(Task& task) {
    auto request = task.io;
    task.io = nullptr;
    destroy(request);
}

static int import_vectors(Task& task, IoRequest& request, uint64_t pointer, size_t count) {
    if (count > 1024)
        return -22;
    request.count = count;
    if (!count)
        return 0;
    request.vectors = static_cast<Iovec*>(alloc(count * sizeof(Iovec)));
    if (!request.vectors)
        return -12;
    if (!task.memory->space.copy_in(request.vectors, pointer, count * sizeof(Iovec)))
        return -14;
    uint64_t total = 0;
    for (size_t i = 0; i < count; i++) {
        auto& v = request.vectors[i];
        if (v.length > INT64_MAX - total)
            return -22;
        total += v.length;
    }
    // Linux limits each operation to MAX_RW_COUNT, including vector operations.
    size_t remaining = 0x7ffff000;
    for (size_t i = 0; i < count; i++) {
        auto& v = request.vectors[i];
        v.length = min(v.length, uint64_t(remaining));
        remaining -= v.length;
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
    uint64_t address = f.rax == 44 ? f.r8 : 0;
    uint64_t address_length = f.rax == 44 ? f.r9 : 0;
    if (f.rax == 19 || f.rax == 20) {
        int error = import_vectors(task, request, f.rsi, f.rdx);
        if (error)
            return error;
    } else if (f.rax == 46 || f.rax == 47) {
        Message message;
        if (!task.memory->space.copy_in(&message, f.rsi, sizeof(message)))
            return -14;
        if (request.write && message.control_length)
            return -95;
        if (request.write) {
            address = message.name;
            address_length = message.name_length;
        } else {
            request.address_pointer = message.name;
            request.address_capacity = message.name_length;
        }
        int error = import_vectors(task, request, message.iov, message.iov_count);
        if (error)
            return error;
    } else {
        request.single = {f.rsi, min(f.rdx, uint64_t(0x7ffff000))};
        request.vectors = &request.single;
        request.count = 1;
    }
    if (request.write && address) {
        if (request.handle->netlink) {
            if (address_length < sizeof(NetlinkAddress))
                return -22;
            if (!task.memory->space.copy_in(&request.netlink_destination, address,
                                            sizeof(NetlinkAddress)))
                return -14;
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
        if (!task.memory->space.copy_in(&request.address_capacity, f.r9, 4))
            return -14;
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
    } else if (request.handle->inet) {
        int error = inet_target(request.handle->inet, request.inet_destination, address != 0);
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
    if (request.packet_length) {
        request.packet_data = static_cast<uint8_t*>(alloc(request.packet_length));
        if (!request.packet_data)
            return -12;
    }
    size_t at = 0;
    for (size_t i = 0; i < request.count; i++) {
        const auto& vector = request.vectors[i];
        if (vector.length &&
            !task.memory->space.copy_in(request.packet_data + at, vector.base, vector.length))
            return -14;
        at += vector.length;
    }
    return 0;
}

static int prepare(Task& task, IoRequest& request) {
    const auto& f = request.call;
    if (f.rax == 73) {
        request.locking = true;
        return 0;
    }
    if (request.handle->socket && request.handle->socket->type != 1)
        return -95;
    request.write = f.rax == 1 || f.rax == 18 || f.rax == 20 || f.rax == 44 || f.rax == 46;
    request.socket = f.rax == 44 || f.rax == 45 || f.rax == 46 || f.rax == 47;
    request.accept = f.rax == 43 || f.rax == 288;
    request.positioned = f.rax == 17 || f.rax == 18;
    if ((request.socket || request.accept) && !request.handle->socket && !request.handle->packet &&
        !request.handle->inet && !request.handle->netlink)
        return -88;
    if (!request.socket && !request.accept &&
        ((request.handle->flags & 3) == (request.write ? 0u : 1u)))
        return -9;
    if (request.socket)
        request.flags = f.rax == 46 || f.rax == 47 ? f.rdx : f.r10;
    if (request.handle->packet || request.handle->inet || request.handle->netlink)
        return prepare_packet(task, request);
    if (request.accept) {
        if (f.rax == 288 && (f.r10 & ~uint64_t(0x80800)))
            return -22;
        return 0;
    }
    if (request.positioned) {
        if (request.handle->pipe || request.handle->socket ||
            (request.handle->node && (request.handle->node->mode & 0170000) == character))
            return -29;
        if (int64_t(f.r10) < 0)
            return -22;
    }
    if (request.socket) {
        request.flags = f.rax == 46 || f.rax == 47 ? f.rdx : f.r10;
        if (request.flags & ~unsigned(2 | 0x40 | 0x4000))
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
        if (message.name)
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

static int64_t transfer(Task& task, IoRequest& request, const Iovec& vector, size_t peek_offset) {
    auto h = request.handle;
    if (!task.memory->space.valid(vector.base, vector.length, !request.write))
        return -14;
    uint8_t buffer[4096];
    size_t done = 0;
    while (done < vector.length) {
        size_t count = min(size_t(vector.length - done), sizeof(buffer));
        if (request.write && !task.memory->space.copy_in(buffer, vector.base + done, count))
            return done ? int64_t(done) : -14;
        int64_t n;
        if (request.socket)
            n = request.write
                    ? socket_write(h->socket, buffer, count)
                    : socket_read(h->socket, buffer, count, request.flags & 2, peek_offset + done);
        else
            n = request.write ? write_handle(h, buffer, count) : read_handle(h, buffer, count);
        if (n < 0) {
            if (n == -32 && request.write && !(request.socket && (request.flags & 0x4000)))
                queue_signal(&task, 13, task.process->pid);
            return done ? int64_t(done) : n;
        }
        if (!request.write && n && !task.memory->space.copy_out(vector.base + done, buffer, n))
            return done ? int64_t(done) : -14;
        done += n;
        if (size_t(n) < count || (!request.write && !request.socket && h->node &&
                                  (h->node->mode & 0170000) == character))
            break;
    }
    return done;
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
                             request.packet_length);
        int result = net_send(request.destination_index, request.packet_data, request.packet_length,
                              request.handle->packet);
        return result ? result : int64_t(request.packet_length);
    }
    if (!request.socket && !request.packet_length)
        return 0;
    if (request.handle->inet)
        if (int error = inet_error(request.handle->inet, true))
            return -error;
    auto frame = request.handle->packet ? packet_front(request.handle->packet) : nullptr;
    auto ip = request.handle->inet ? inet_front(request.handle->inet) : nullptr;
    auto nl = request.handle->netlink ? netlink_front(request.handle->netlink) : nullptr;
    if (!frame && !ip && !nl) {
        if (request.handle->netlink)
            return -11;
        if (request.handle->inet) {
            int error = inet_error(request.handle->inet, true);
            bool blocking = !(request.handle->flags & 04000) && !(request.flags & 0x40);
            return error ? -error : blocking && (inet_shutdown(request.handle->inet) & 1) ? 0 : -11;
        }
        auto info = net_info(packet_interface(request.handle->packet));
        return info && !info->live ? -5 : -11;
    }
    size_t length = nl ? nl->length : ip ? ip->length : frame->length;
    const auto bytes = nl ? netlink_bytes(nl) : ip ? inet_bytes(ip) : packet_bytes(frame);
    const void* source = nl   ? static_cast<const void*>(&nl->source)
                         : ip ? static_cast<const void*>(&ip->source)
                              : &frame->source;
    const auto copy_fault = [&request]() -> int64_t {
        // Linux raw Internet receives dequeue even when a non-peek copy faults.
        if (request.handle->inet && !(request.flags & 2))
            inet_consume(request.handle->inet);
        if (request.handle->netlink && !(request.flags & 2))
            netlink_consume(request.handle->netlink);
        return -14;
    };
    size_t remaining = min(length, request.packet_length), at = 0;
    for (size_t i = 0; i < request.count && remaining; i++) {
        const auto& vector = request.vectors[i];
        size_t count = min(remaining, size_t(vector.length));
        if (count && !task.memory->space.copy_out(vector.base, bytes + at, count))
            return copy_fault();
        at += count;
        remaining -= count;
    }
    uint32_t actual_address = nl   ? sizeof(NetlinkAddress)
                              : ip ? sizeof(InetAddress)
                                   : sizeof(PacketAddress);
    if (request.address_pointer &&
        (!task.memory->space.copy_out(request.address_pointer, source,
                                      min(request.address_capacity, actual_address)) ||
         (request.address_length_pointer &&
          !task.memory->space.copy_out(request.address_length_pointer, &actual_address, 4))))
        return copy_fault();
    if (f.rax == 47) {
        uint32_t flags = length > request.packet_length ? 0x20 : 0;
        uint64_t control_length = 0;
        uint32_t address_length = request.address_pointer ? actual_address : 0;
        if (!task.memory->space.copy_out(f.rsi + offsetof(Message, name_length), &address_length,
                                         4) ||
            !task.memory->space.copy_out(f.rsi + offsetof(Message, control_length), &control_length,
                                         8) ||
            !task.memory->space.copy_out(f.rsi + offsetof(Message, flags), &flags, 4))
            return copy_fault();
    }
    int64_t result = request.flags & 0x20 ? length : at;
    if (!(request.flags & 2)) {
        if (request.handle->netlink)
            netlink_consume(request.handle->netlink);
        else if (request.handle->inet)
            inet_consume(request.handle->inet);
        else
            packet_consume(request.handle->packet);
    }
    return result;
}

static int64_t attempt(Task& task, IoRequest& request) {
    auto h = request.handle;
    const auto& f = request.call;
    if (request.locking) {
        int result = file_lock_try(h, uint32_t(f.rsi));
        return result == -11 && !(f.rsi & 4) ? would_block : result;
    }
    if (h->packet || h->inet || h->netlink) {
        int64_t result = packet_attempt(task, request);
        if (result == -11 && !(h->flags & 04000) && !(request.flags & 0x40))
            return would_block;
        return result;
    }
    if (request.accept)
        return socket_accept(task, h, f.rsi, f.rdx, f.rax == 288 ? f.r10 : 0);
    size_t done = 0;
    int64_t result = 0;
    uint64_t old_offset = h->offset;
    if (request.positioned)
        h->offset = f.r10;
    for (size_t i = 0; i < request.count; i++) {
        auto& vector = request.vectors[i];
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
    if (result == -11 && !(h->flags & 04000) && !(request.flags & 0x40) && !request.positioned)
        return would_block;
    if (result >= 0 && f.rax == 45 && f.r8) {
        int error =
            socket_output_address(task, h->socket->peer ? h->socket->peer : h->socket, f.r8, f.r9);
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
    }
    return result;
}

int64_t io_syscall(Task& task, const Frame& frame) {
    // Linux validates the operation before looking up the descriptor.
    if (frame.rax == 73 && !file_lock_operation(uint32_t(frame.rsi)))
        return -22;
    int fd = int(frame.rdi);
    Handle* h = fd >= 0 && unsigned(fd) < max_fds ? task.files->entries[fd].handle : nullptr;
    if (!h)
        return -9;
    if (task.io)
        panic("active I/O at syscall entry");
    auto request = static_cast<IoRequest*>(alloc(sizeof(IoRequest)));
    if (!request)
        return -12;
    *request = {};
    request->handle = h;
    request->call = frame;
    retain(h);
    int error = prepare(task, *request);
    int64_t result = error ? error : attempt(task, *request);
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
    if (!request->locking && !request->handle->packet && !request->handle->inet &&
        !request->handle->netlink && !handle_ready(request->handle, request->write) &&
        !(request->handle->flags & 04000))
        return false;
    int64_t result = attempt(task, *request);
    if (result == would_block)
        return false;
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
