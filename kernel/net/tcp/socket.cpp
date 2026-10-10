// SPDX-License-Identifier: GPL-3.0-or-later
#include "net/tcp/socket.hpp"
#include "net/tcp/connection.hpp"
#include "net/tcp/isn.hpp"
#include "net/ipv4.hpp"
#include "net/ipv4_wire.hpp"
#include "core/random.hpp"
#include "core/time.hpp"
#include "process/task.hpp"
#include "../ipv4/socket.hpp"
#include <new>

namespace ax {
namespace {
uint8_t sequence_key[32];
bool sequence_seeded;
uint64_t sequence_clock;
bool polling;

uint64_t now_ms() {
    clock_refresh();
    return ticks > UINT64_MAX / 10 ? UINT64_MAX : ticks * 10;
}

int sequence(InetSocket* socket, uint32_t& value, uint64_t now) {
    if (!sequence_seeded) {
        int error = random_read(sequence_key, sizeof(sequence_key));
        if (error)
            return error;
        sequence_seeded = true;
    }
    uint64_t clock = now > UINT64_MAX / 250 ? UINT64_MAX : now * 250;
    sequence_clock = max(clock, sequence_clock == UINT64_MAX ? sequence_clock : sequence_clock + 1);
    value = tcp::initial_sequence(sequence_key, socket->local, socket->peer, socket->local_port,
                                  __builtin_bswap16(socket->peer_port), sequence_clock);
    return 0;
}

bool make_stream(InetSocket* socket) {
    void* storage = alloc(sizeof(tcp::Connection));
    if (!storage)
        return false;
    socket->stream = new (storage) tcp::Connection;
    tcp_limits(socket);
    return true;
}

void unqueue(InetSocket* socket) {
    auto listener = socket->listener;
    if (!listener)
        return;
    if (socket->accept_queued) {
        for (unsigned at = 0; at < listener->accept_count; at++)
            if (listener->accepted[at] == socket) {
                for (unsigned next = at + 1; next < listener->accept_count; next++)
                    listener->accepted[next - 1] = listener->accepted[next];
                listener->accepted[--listener->accept_count] = nullptr;
                break;
            }
    }
    if (listener->children)
        listener->children--;
    socket->listener = nullptr;
    socket->accept_queued = false;
}

void reclaim(InetSocket* socket) {
    unqueue(socket);
    if (socket->stream) {
        socket->stream->~Connection();
        release(socket->stream);
        socket->stream = nullptr;
    }
    inet_dispose(socket);
}

void stop_listener(InetSocket* socket) {
    socket->listening = false;
    for (auto& child : inet_sockets)
        if (child.used && child.listener == socket) {
            unqueue(&child);
            child.detached = true;
            if (child.stream)
                child.stream->abort(0, true);
            else
                reclaim(&child);
        }
}

int emit(InetSocket* owner, unsigned index, uint32_t local, uint32_t peer,
         const tcp::Segment& segment, uint8_t ttl) {
    uint8_t bytes[1480];
    size_t size = tcp::encode(local, peer, segment, bytes, sizeof(bytes));
    if (!size)
        return -90;
    return ipv4_send(owner, local, peer, index, 6, ttl, false, bytes, size);
}

int address_out(Task& task, const InetAddress& address, uint64_t pointer, uint64_t length_pointer) {
    uint32_t length, actual = sizeof(address);
    if (!task.memory->space.copy_in(&length, length_pointer, 4) ||
        !task.memory->space.copy_out(pointer, &address, min(length, actual)) ||
        !task.memory->space.copy_out(length_pointer, &actual, 4))
        return -14;
    return 0;
}

bool synchronized(const InetSocket* socket) {
    if (!socket->stream)
        return false;
    auto state = socket->stream->state();
    return state != tcp::State::closed && state != tcp::State::syn_sent &&
           state != tcp::State::syn_received && state != tcp::State::time_wait;
}
} // namespace

bool inet_stream(InetSocket* socket) {
    return socket && socket->type == 1;
}

void tcp_limits(InetSocket* socket) {
    if (!socket->stream)
        return;
    socket->stream->limits(socket->receive_limit / 2, socket->send_limit / 2);
    socket->stream->nodelay(socket->nodelay);
    socket->stream->user_timeout(socket->user_timeout);
}

void tcp_close(InetSocket* socket) {
    if (socket->listening) {
        stop_listener(socket);
        inet_dispose(socket);
        return;
    }
    if (!socket->stream) {
        inet_dispose(socket);
        return;
    }
    unqueue(socket);
    socket->detached = true;
    socket->stream->detach(now_ms());
}

int tcp_error(InetSocket* socket, bool clear) {
    int error = socket->error;
    if (!error && socket->stream && !socket->error_seen)
        error = socket->stream->error();
    if (clear) {
        socket->error = 0;
        if (error)
            socket->error_seen = true;
    }
    return error;
}

void tcp_failed(InetSocket* socket, int error) {
    if (!socket || !socket->used)
        return;
    if (socket->stream && socket->stream->state() == tcp::State::closed)
        return;
    if (!tcp_error(socket, false))
        socket->error = error;
    if (socket->stream && socket->stream->state() != tcp::State::closed)
        socket->stream->abort(error);
}

int tcp_connect(InetSocket* socket, const InetAddress& address) {
    if (socket->listening)
        return -106;
    if (socket->stream)
        return socket->stream->state() == tcp::State::syn_sent ||
                       socket->stream->state() == tcp::State::syn_received
                   ? -114
                   : -106;
    if (address.family != 2)
        return -97;
    uint32_t peer = __builtin_bswap32(address.address);
    if (!peer)
        peer = 0x7f000001;
    Ipv4Path path;
    int error = ipv4_path(socket->bound ? socket->local : 0, peer, socket->index, path);
    if (error)
        return error;
    if (!socket->local_port) {
        error = inet_bind_port(socket, socket->bound ? socket->local : 0, 0);
        if (error)
            return error;
    }
    for (auto& other : inet_sockets)
        if (other.used && &other != socket && other.type == 1 && other.stream &&
            other.local == path.source && other.peer == peer &&
            other.local_port == socket->local_port && other.peer_port == address.port)
            return -99;
    socket->local = path.source;
    socket->peer = peer;
    socket->peer_port = address.port;
    socket->stream_index = path.index;
    uint64_t now = now_ms();
    uint32_t initial;
    error = sequence(socket, initial, now);
    if (error)
        return error;
    if (!make_stream(socket))
        return -12;
    uint16_t mss = min(socket->maximum_segment, uint16_t(path.mtu > 40 ? path.mtu - 40 : 1));
    socket->stream->active(initial, now, mss);
    tcp_poll();
    return -115;
}

int64_t tcp_connect_result(InetSocket* socket) {
    if (!socket->stream)
        return -107;
    auto state = socket->stream->state();
    if (state == tcp::State::syn_sent || state == tcp::State::syn_received)
        return would_block;
    return socket->stream->error() ? -socket->stream->error() : 0;
}

int tcp_listen(InetSocket* socket, int backlog) {
    if (socket->stream)
        return -22;
    if (!socket->local_port) {
        int error = inet_bind_port(socket, socket->local, 0);
        if (error)
            return error;
    }
    for (auto& other : inet_sockets)
        if (other.used && &other != socket && other.type == 1 && other.listening &&
            other.local_port == socket->local_port &&
            (!other.local || !socket->local || other.local == socket->local) &&
            (!other.index || !socket->index || other.index == socket->index))
            return -98;
    socket->listening = true;
    socket->shutdown = 0;
    socket->backlog =
        backlog < 0 ? inet_queue_count : min(unsigned(max(1, backlog)), inet_queue_count);
    return 0;
}

int tcp_address(Task& task, InetSocket* socket, bool peer, uint64_t pointer, uint64_t length) {
    if (peer && !synchronized(socket))
        return -107;
    InetAddress address{2,
                        uint16_t(peer ? socket->peer_port : __builtin_bswap16(socket->local_port)),
                        __builtin_bswap32(peer ? socket->peer : socket->local),
                        {}};
    return address_out(task, address, pointer, length);
}

int64_t tcp_accept(Task& task, Handle* handle, uint64_t address, uint64_t length, unsigned flags) {
    auto socket = handle->inet;
    if (!socket || !socket->listening)
        return -22;
    if (!socket->accept_count)
        return (handle->flags & 04000) ? -11 : would_block;
    auto accepted = socket->accepted[0];
    if (accepted->stream->state() == tcp::State::closed) {
        reclaim(accepted);
        return -103;
    }
    auto opened = open_handle(nullptr, 2 | ((flags & 0x800) ? 04000 : 0));
    if (!opened)
        return -23;
    opened->inet = accepted;
    int fd = allocate_fd(&task, opened, 0, flags & 0x80000);
    if (fd < 0) {
        opened->inet = nullptr;
        close_handle(opened);
        return fd;
    }
    unqueue(accepted);
    if (address) {
        int error = tcp_address(task, accepted, true, address, length);
        if (error) {
            task.files->entries[fd] = {};
            close_handle(opened);
            return error;
        }
    }
    return fd;
}

int64_t tcp_read(InetSocket* socket, void* data, size_t length, bool peek, size_t offset) {
    auto stream = socket->stream;
    if (!stream)
        return -107;
    if (stream->available())
        return stream->read(data, length, peek, peek ? offset : 0);
    if (int error = tcp_error(socket, true))
        return -error;
    if (stream->eof() || stream->state() == tcp::State::closed ||
        stream->state() == tcp::State::time_wait)
        return 0;
    return length ? -11 : 0;
}

int64_t tcp_write(InetSocket* socket, const void* data, size_t length) {
    if (int error = tcp_error(socket, true))
        return -error;
    if (!socket->stream || (socket->shutdown & 2) ||
        socket->stream->state() == tcp::State::closed ||
        socket->stream->state() == tcp::State::time_wait)
        return -32;
    if (!synchronized(socket))
        return -11;
    if (!length)
        return 0;
    size_t count = socket->stream->write(data, length, now_ms());
    tcp_poll();
    return count ? int64_t(count) : -11;
}

unsigned tcp_shutdown_state(InetSocket* socket) {
    unsigned state = socket->shutdown;
    if (socket->stream && socket->stream->eof())
        state |= 1;
    return state;
}

int tcp_shutdown(InetSocket* socket, unsigned operation) {
    if (operation > 2)
        return -22;
    if (socket->listening) {
        if (operation != 1)
            stop_listener(socket);
        return 0;
    }
    socket->shutdown |= operation == 0 ? 1 : operation == 1 ? 2 : 3;
    if (!socket->stream)
        return -107;
    if (operation != 1)
        socket->stream->close_read();
    if (operation != 0)
        socket->stream->close_write();
    tcp_poll();
    return synchronized(socket) ? 0 : -107;
}

size_t tcp_available(InetSocket* socket) {
    return socket->stream ? socket->stream->available() : 0;
}

uint32_t tcp_events(InetSocket* socket) {
    if (socket->listening)
        return socket->accept_count ? 1 : 0;
    if (!socket->stream)
        return 4 | 16;
    auto stream = socket->stream;
    uint32_t events = tcp_error(socket, false) ? 8 : 0;
    auto state = stream->state();
    if (state == tcp::State::closed || state == tcp::State::time_wait)
        return events | 1 | 4 | 16 | 0x2000;
    if (stream->available() || stream->eof())
        events |= 1;
    if (stream->writable() || (socket->shutdown & 2))
        events |= 4;
    if (stream->eof())
        events |= 0x2000;
    return events;
}

bool tcp_ready(InetSocket* socket, bool write) {
    return tcp_events(socket) & ((write ? 4 : 1) | 8 | 16);
}

bool tcp_option(InetSocket* socket, unsigned option, int& value, bool set, int& error) {
    error = 0;
    if (option == 1) {
        if (set) {
            socket->nodelay = value != 0;
            tcp_limits(socket);
        } else
            value = socket->nodelay;
    } else if (option == 2) {
        if (set) {
            if (value && (value < 88 || value > 32767))
                error = -22;
            else if (socket->stream)
                error = -95;
            else
                socket->maximum_segment = value ? min(value, 1460) : 1460;
        } else
            value = socket->maximum_segment;
    } else if (option == 18) {
        if (set) {
            if (value < 0)
                error = -22;
            else {
                socket->user_timeout = value;
                tcp_limits(socket);
            }
        } else
            value = socket->user_timeout;
    } else
        return false;
    return true;
}

void tcp_receive(unsigned index, uint32_t source, uint32_t destination, const void* data,
                 size_t size) {
    tcp::Segment segment;
    if (!tcp::decode(source, destination, data, size, segment))
        return;
    uint64_t now = now_ms();
    InetSocket* listener = nullptr;
    for (auto& socket : inet_sockets) {
        if (!socket.used || socket.type != 1 || socket.local_port != segment.destination ||
            (socket.index && socket.index != index))
            continue;
        if (socket.stream && socket.local == destination && socket.peer == source &&
            socket.peer_port == __builtin_bswap16(segment.source) && socket.stream_index == index) {
            socket.stream->input(segment, now);
            if (socket.listener && !socket.accept_queued && synchronized(&socket)) {
                auto parent = socket.listener;
                if (parent->accept_count < inet_queue_count) {
                    parent->accepted[parent->accept_count++] = &socket;
                    socket.accept_queued = true;
                }
            }
            return;
        }
        if (socket.listening && (!socket.local || socket.local == destination) &&
            (!listener || (socket.local && !listener->local)))
            listener = &socket;
    }
    if (segment.flags & tcp::rst)
        return;
    if (listener && (segment.flags & tcp::syn) && !(segment.flags & (tcp::ack | tcp::fin))) {
        if (listener->children >= listener->backlog)
            return;
        auto child = inet_allocate(1);
        if (!child)
            return;
        child->local = destination;
        child->peer = source;
        child->local_port = segment.destination;
        child->peer_port = __builtin_bswap16(segment.source);
        child->index = listener->index;
        child->stream_index = index;
        child->receive_limit = listener->receive_limit;
        child->send_limit = listener->send_limit;
        child->reuse = listener->reuse;
        child->nodelay = listener->nodelay;
        child->user_timeout = listener->user_timeout;
        child->maximum_segment = listener->maximum_segment;
        uint32_t initial;
        if (sequence(child, initial, now) || !make_stream(child)) {
            reclaim(child);
            return;
        }
        const auto info = index == ipv4_loopback ? nullptr : net_info(index);
        uint16_t mss =
            info ? min(child->maximum_segment, uint16_t(info->mtu > 40 ? info->mtu - 40 : 1))
                 : child->maximum_segment;
        if (!child->stream->passive(initial, segment, now, mss)) {
            reclaim(child);
            return;
        }
        child->listener = listener;
        listener->children++;
        return;
    }
    tcp::Segment reset{};
    reset.source = segment.destination;
    reset.destination = segment.source;
    reset.flags = tcp::rst;
    if (segment.flags & tcp::ack)
        reset.sequence = segment.acknowledgment;
    else {
        reset.flags |= tcp::ack;
        reset.acknowledgment = segment.sequence + tcp::sequence_length(segment);
    }
    emit(nullptr, index, destination, source, reset, 64);
}

void tcp_poll() {
    if (polling)
        return;
    polling = true;
    uint64_t now = now_ms();
    for (auto& socket : inet_sockets) {
        if (!socket.used || socket.type != 1 || !socket.stream)
            continue;
        if (socket.stream_index && socket.stream_index != ipv4_loopback) {
            auto info = net_info(socket.stream_index);
            if (!info || !info->live)
                tcp_failed(&socket, 5);
        }
        tcp::Segment segment;
        bool pending = socket.stream->next(now, segment);
        for (unsigned at = 0; pending && at < 4; at++) {
            segment.source = socket.local_port;
            segment.destination = __builtin_bswap16(socket.peer_port);
            int error =
                emit(&socket, socket.stream_index, socket.local, socket.peer, segment, socket.ttl);
            if (error == -11 || error == -12 || error == -105)
                break;
            if (error) {
                tcp_failed(&socket, -error);
                pending = false;
                break;
            }
            socket.stream->emitted(now);
            pending = socket.stream->next(now, segment);
        }
        if (!pending && socket.stream->state() == tcp::State::closed &&
            (socket.detached || (socket.listener && !socket.accept_queued)))
            reclaim(&socket);
    }
    polling = false;
}
} // namespace ax
