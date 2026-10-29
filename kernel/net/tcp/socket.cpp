// SPDX-License-Identifier: GPL-3.0-or-later
#include "net/tcp/socket.hpp"
#include "net/tcp/connection.hpp"
#include "net/tcp/icmp.hpp"
#include "net/tcp/isn.hpp"
#include "net/ipv4.hpp"
#include "net/ipv4_wire.hpp"
#include "core/random.hpp"
#include "core/time.hpp"
#include "process/task.hpp"
#include "fs/descriptor.hpp"
#include "../ipv4/socket.hpp"
#include <new>

namespace ax {
namespace {
uint8_t sequence_key[32];
bool sequence_seeded;
uint64_t sequence_clock;
bool polling;

struct HeaderOptions {
    uint8_t ttl = 64, tos = 0;
    int16_t hops = -1;
    uint8_t traffic_class = 0;
};

HeaderOptions header_options(const InetSocket& socket) {
    return {socket.ttl, socket.tos, socket.hops, socket.traffic_class};
}

// Pending requests use the live listener's headers. The final ACK takes
// the last snapshot; accepted descriptions then own independent controls.
// Multicast flag getters retain that same independent listener snapshot.
void inherit_ip_controls(InetSocket& socket, const InetSocket& listener) {
    if (socket.tos != listener.tos || socket.traffic_class != listener.traffic_class) {
        socket.destination = {};
        ipv6_destination_clear(socket.destination6);
    }
    socket.ttl = listener.ttl;
    socket.tos = listener.tos;
    socket.receive_options = listener.receive_options;
    socket.hops = listener.hops;
    socket.traffic_class = listener.traffic_class;
    socket.multicast.loop = listener.multicast.loop;
    socket.multicast.all = listener.multicast.all;
}

struct TimeWaitRecord {
    tcp::TimeWait state;
    tcp::Address local, peer;
    uint16_t local_port = 0, peer_port = 0;
    unsigned binding_index = 0;
    uint8_t traffic_class = 0;
    bool used = false, pending = false, reuse = false, reserved = false;
};

static_assert(sizeof(TimeWaitRecord) <= 96);
TimeWaitRecord time_waits[tcp_time_wait_count];

uint64_t now_ms() {
    clock_refresh();
    return ticks > UINT64_MAX / 10 ? UINT64_MAX : ticks * 10;
}

void expire_time_wait(uint64_t now) {
    for (auto& record : time_waits)
        if (record.used && now >= record.state.deadline)
            record.used = false;
}

int sequence(InetSocket* socket, uint32_t& value, uint64_t now) {
    // Disconnect advances this description beyond every byte it could emit.
    // Carry that sequence through intervening destinations as well as the last
    // tuple: choosing a new tuple hash could re-enter an earlier stream.
    if (socket->restart_valid) {
        value = socket->restart_sequence;
        return 0;
    }
    if (!sequence_seeded) {
        int error = random_read(sequence_key, sizeof(sequence_key));
        if (error)
            return error;
        sequence_seeded = true;
    }
    uint64_t clock = now > UINT64_MAX / 250 ? UINT64_MAX : now * 250;
    sequence_clock = max(clock, sequence_clock == UINT64_MAX ? sequence_clock : sequence_clock + 1);
    value =
        socket->wire6
            ? tcp::initial_sequence(sequence_key, socket->local6, socket->peer6, socket->local_port,
                                    __builtin_bswap16(socket->peer_port), sequence_clock)
            : tcp::initial_sequence(sequence_key, socket->local, socket->peer, socket->local_port,
                                    __builtin_bswap16(socket->peer_port), sequence_clock);
    return 0;
}

void release_time_wait(InetSocket* socket) {
    if (socket->time_wait_slot < tcp_time_wait_count) {
        auto& record = time_waits[socket->time_wait_slot];
        if (record.reserved && !record.used)
            record.reserved = false;
        socket->time_wait_slot = UINT16_MAX;
    }
}

int make_stream(InetSocket* socket, uint64_t now) {
    expire_time_wait(now);
    for (unsigned index = 0; index < tcp_time_wait_count; index++)
        if (!time_waits[index].used && !time_waits[index].reserved) {
            time_waits[index].reserved = true;
            socket->time_wait_slot = index;
            break;
        }
    // Every admitted connection can leave the shared Internet pool after close.
    // A full table rejects new TCP state instead of retaining large orphan owners.
    if (socket->time_wait_slot == UINT16_MAX)
        return -105;
    void* storage = alloc(sizeof(tcp::Connection));
    if (!storage) {
        release_time_wait(socket);
        return -12;
    }
    socket->stream =
        new (storage) tcp::Connection(socket->wire6 ? tcp::Family::ipv6 : tcp::Family::ipv4);
    tcp_limits(socket);
    return 0;
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
    release_time_wait(socket);
    if (socket->stream) {
        socket->stream->~Connection();
        release(socket->stream);
        socket->stream = nullptr;
    }
    inet_dispose(socket);
}

void release_automatic_port(InetSocket* socket) {
    if (!socket->port_locked && socket->local_port) {
        // Linux releases the bind owner but keeps inet_sport for getsockname.
        socket->reported_port = socket->local_port;
        socket->local_port = 0;
        socket->order = 0;
    }
}

void reset_connect(InetSocket* socket) {
    // Owned packets may outlive this attempt; their callbacks cannot reach its successor.
    ipv4_detach_owner(socket);
    ipv6_detach_output(socket);
    socket->destination = {};
    ipv6_destination_clear(socket->destination6);
    release_time_wait(socket);
    socket->mss_cache = socket->stream->segment_size();
    socket->stream->~Connection();
    release(socket->stream);
    socket->stream = nullptr;
    release_automatic_port(socket);
    if (!socket->bound) {
        socket->local = 0;
        socket->local6 = {};
        socket->wire6 = socket->ipv6;
    }
    socket->peer6 = {};
    socket->peer = 0;
    socket->peer_port = 0;
    socket->transmitted = 0;
    socket->shutdown = 0;
    socket->error = 0;
    socket->error_seen = false;
    socket->connect_pending = false;
}

bool transfer_time_wait(InetSocket* socket) {
    if (socket->time_wait_slot >= tcp_time_wait_count)
        return false;
    auto& record = time_waits[socket->time_wait_slot];
    if (!record.reserved || record.used)
        return false;
    record = {};
    record.state = socket->stream->time_wait_state();
    record.local = socket->stream_local();
    record.peer = socket->stream_peer();
    record.local_port = socket->local_port;
    record.peer_port = socket->peer_port;
    record.binding_index = socket->index;
    // The closed IPv6 description retains its traffic class for both wire
    // families. IPv4 descriptions retain TOS. Replies use default hops.
    record.traffic_class = socket->ipv6 ? socket->traffic_class : socket->tos;
    record.reuse = socket->reuse;
    record.used = true;
    socket->time_wait_slot = UINT16_MAX;
    return true;
}

bool compact_time_wait(InetSocket* socket) {
    if (!transfer_time_wait(socket))
        return false;
    reclaim(socket);
    return true;
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

void output_complete(void* identity, size_t bytes, int error, unsigned index) {
    auto socket = static_cast<InetSocket*>(identity);
    if (error == -125 || (error == -90 && tcp6_path_mtu(socket, bytes)))
        return;
    if (error)
        tcp_failed(socket, -error, index);
}

int emit(InetSocket* owner, unsigned index, const tcp::Address& local, const tcp::Address& peer,
         const tcp::Segment& segment, const HeaderOptions& options) {
    uint8_t bytes[1480];
    size_t size = local.is_ipv4()
                      ? tcp::encode(local.ipv4(), peer.ipv4(), segment, bytes, sizeof(bytes))
                      : tcp::encode(local.bytes, peer.bytes, segment, bytes, sizeof(bytes));
    if (!size)
        return -90;
    if (local.is_ipv4())
        return ipv4_send(owner, local.ipv4(), peer.ipv4(), index, 6, options.ttl, false, bytes,
                         size, true, options.tos);
    return ipv6_send_owned({owner, owner ? output_complete : nullptr}, local.bytes, peer.bytes,
                           index, 6, options.hops, bytes, size, tcp6_source_policy(owner),
                           options.traffic_class, owner ? &owner->destination6 : nullptr);
}

int address_out(Task& task, const void* address, uint32_t actual, uint64_t pointer,
                uint64_t length_pointer) {
    uint32_t length;
    if (!task.memory->space.copy_in(&length, length_pointer, 4))
        return -14;
    if (int32_t(length) < 0)
        return -22;
    auto bytes = static_cast<const uint8_t*>(address);
    size_t remaining = min(length, actual);
    while (remaining) {
        size_t copied = min(remaining, size_t(page_size - pointer % page_size));
        if (!task.memory->space.copy_out(pointer, bytes, copied))
            return -14;
        pointer += copied;
        bytes += copied;
        remaining -= copied;
    }
    if (!task.memory->space.copy_out(length_pointer, &actual, 4))
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

int disconnect(InetSocket* socket) {
    int error = tcp_error(socket, false);
    if (socket->listening)
        stop_listener(socket);
    if (socket->stream) {
        auto state = socket->stream->state();
        // A completed tuple remains protected even when its description is reused.
        if (state == tcp::State::time_wait && !transfer_time_wait(socket))
            return -105;
        if (state != tcp::State::closed && state != tcp::State::time_wait)
            error = 104;
        socket->restart_sequence = socket->stream->reconnect_sequence();
        socket->restart_valid = true;
        socket->generation++;
        socket->stream->abort(0, state != tcp::State::closed && state != tcp::State::syn_sent &&
                                     state != tcp::State::time_wait);
        tcp_poll();
        reset_connect(socket);
    } else {
        socket->generation++;
        tcp_poll();
        release_automatic_port(socket);
        if (!socket->bound) {
            socket->local = 0;
            socket->local6 = {};
            socket->wire6 = socket->ipv6;
        }
        socket->peer6 = {};
        socket->peer = 0;
        socket->peer_port = 0;
        socket->shutdown = 0;
        socket->error_seen = false;
    }
    socket->user_mss = 0;
    socket->error = error;
    return 0;
}
} // namespace

Ipv6SourcePolicy tcp6_source_policy(const InetSocket* socket) {
    if (socket) {
        if (socket->bound)
            return Ipv6SourcePolicy::retained;
        if (socket->stream) {
            auto state = socket->stream->state();
            if (state != tcp::State::closed && state != tcp::State::time_wait)
                return Ipv6SourcePolicy::retained;
        }
    }
    return Ipv6SourcePolicy::assigned;
}

bool inet_stream(InetSocket* socket) {
    return socket && socket->type == 1;
}

uint64_t tcp_generation(const InetSocket* socket) {
    return socket ? socket->generation : 0;
}

int tcp_cancelled_write_error(InetSocket* socket) {
    if (!socket->stream)
        if (int error = tcp_error(socket, true))
            return error;
    return 32;
}

bool tcp_port_busy(uint32_t local, uint16_t port, unsigned index, bool reuse) {
    return tcp_port_busy({tcp::Address::ipv4(local), index, false}, port, reuse);
}

bool tcp_port_busy(const tcp::Binding& binding, uint16_t port, bool reuse) {
    expire_time_wait(now_ms());
    for (auto& record : time_waits)
        if (record.used && record.local_port == port &&
            binding.overlaps({record.local, record.binding_index, false}) &&
            !(reuse && record.reuse))
            return true;
    return false;
}

bool tcp_ipv6(const InetSocket* socket) {
    return socket && socket->type == 1 && socket->ipv6;
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
    uint64_t now = now_ms();
    socket->stream->detach(now);
    if (socket->stream->state() == tcp::State::closed) {
        tcp::Segment pending;
        // Last close releases a failed endpoint immediately. A reset that has
        // not reached output ownership still needs the ordinary poll path.
        if (!socket->stream->next(now, pending))
            reclaim(socket);
    }
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

void tcp_failed(InetSocket* socket, int error, unsigned failed_index) {
    if (!socket || !socket->used)
        return;
    // IPv4 may discard an owned copy when an interface goes down or the copy
    // expires under backpressure. TCP still owns its unacknowledged bytes and
    // retries them on its existing clocks.
    if (error == 100 || error == 105)
        return;
    if (socket->stream && socket->stream->state() == tcp::State::closed)
        return;
    // A discarded copy on a failed device does not end an unbound stream if
    // routing now provides another healthy output device. TCP retains its bytes
    // and its original retransmission and delivery deadlines.
    if (error == 5 && failed_index && !socket->index && socket->stream) {
        if (socket->wire6) {
            Ipv6Path replacement;
            if (!ipv6_path(socket->local6, socket->peer6, 0, replacement) &&
                replacement.index != failed_index)
                return;
        } else {
            Ipv4Path replacement;
            if (!ipv4_path(socket->local, socket->peer, 0, replacement) &&
                replacement.index != failed_index)
                return;
        }
    }
    if (!tcp_error(socket, false))
        socket->error = error;
    if (socket->stream && socket->stream->state() != tcp::State::closed)
        socket->stream->abort(error);
}

int tcp_so_error(InetSocket* socket, bool clear) {
    int error = tcp_error(socket, clear);
    if (!error && socket->stream)
        error = socket->stream->network_error(clear);
    return error;
}

void tcp_icmp_error(unsigned index, const uint8_t* bytes, size_t length) {
    tcp::IcmpError quote;
    if (!tcp::decode_icmp_error(bytes, length, quote))
        return;
    for (auto& socket : inet_sockets) {
        if (!socket.used || socket.type != 1 || socket.wire6 || !socket.stream ||
            socket.listening || socket.local != quote.local || socket.peer != quote.peer ||
            socket.local_port != quote.source ||
            __builtin_bswap16(socket.peer_port) != quote.destination ||
            (socket.index && socket.index != index))
            continue;
        if (quote.too_big) {
            if (!inet_accept_path_mtu(&socket) || !socket.stream->owns_pmtu_quote(quote.sequence))
                continue;
            uint16_t mtu = tcp::quoted_path_mtu(quote);
            if (!mtu)
                continue;
            uint32_t learned = ipv4_learn_pmtu(quote.local, quote.peer, socket.index,
                                               quote.next_hop_mtu, quote.quoted_length);
            if (learned)
                mtu = min(mtu, uint16_t(learned));
            if (learned)
                ipv4_destination(socket.destination, socket.local, socket.peer, socket.index);
            // DONT can populate the route cache without forcing a transport retry.
            // PROBE bypasses that cache at IP output, but TCP still adapts its MSS.
            if (socket.mtu_policy && socket.stream->reduce_mss(quote.sequence, uint16_t(mtu - 40)))
                ipv4_discard_oversized(&socket, mtu);
        } else
            socket.stream->quoted_error(quote.sequence, quote.error, quote.abort_request);
    }
}

namespace {
int connect_to(InetSocket* socket, const tcp::Address& peer, uint16_t port, unsigned index) {
    if (peer.is_ipv4() && (peer.ipv4() >> 28) == 14)
        return -101;
    Ipv4Destination destination4;
    Ipv6Path destination6;
    tcp::Address local;
    uint32_t mtu;
    bool wire6 = !peer.is_ipv4();
    int error;
    if (wire6) {
        error = ipv6_path(socket->bound ? socket->local6 : ip6::Address{}, peer.bytes, index,
                          destination6, false,
                          socket->bound ? Ipv6SourcePolicy::retained : Ipv6SourcePolicy::assigned);
        local = tcp::Address::ipv6(destination6.source);
        mtu = destination6.mtu;
    } else {
        error =
            ipv4_destination(destination4, socket->bound ? socket->local : 0, peer.ipv4(), index);
        local = tcp::Address::ipv4(destination4.path.source);
        mtu = destination4.path.mtu;
    }
    if (error)
        return error;
    socket->wire6 = wire6;
    if (!socket->local_port) {
        error = inet_bind_port(socket, socket->bound ? socket->local : 0, 0);
        if (error)
            return error;
    }
    for (auto& other : inet_sockets)
        if (other.used && &other != socket && other.type == 1 && other.stream &&
            other.stream_local() == local && other.stream_peer() == peer &&
            other.local_port == socket->local_port && other.peer_port == port &&
            (!index || !other.index || index == other.index))
            return -99;
    expire_time_wait(now_ms());
    for (auto& record : time_waits)
        if (record.used && record.local == local && record.peer == peer &&
            record.local_port == socket->local_port && record.peer_port == port &&
            (!index || !record.binding_index || index == record.binding_index))
            return -99;
    if (wire6) {
        socket->local6 = local.bytes;
        socket->peer6 = peer.bytes;
    } else {
        socket->local = local.ipv4();
        socket->peer = peer.ipv4();
    }
    socket->peer_port = port;
    socket->index = index;
    uint64_t now = now_ms();
    uint32_t initial;
    error = sequence(socket, initial, now);
    if (error)
        return error;
    error = make_stream(socket, now);
    if (error)
        return error;
    socket->destination = destination4;
    if (wire6)
        ipv6_destination_store(socket->destination6, destination6, peer.bytes);
    socket->error = 0;
    socket->error_seen = false;
    uint16_t limit = socket->user_mss ? socket->user_mss : 1460;
    unsigned overhead = wire6 ? 60 : 40;
    uint16_t mss = min(limit, uint16_t(mtu > overhead ? min(mtu - overhead, 1460u) : 1));
    socket->stream->active(initial, now, mss);
    socket->connect_pending = true;
    tcp_poll();
    return -115;
}
} // namespace

int tcp_connect(InetSocket* socket, const InetAddress& address) {
    if (!address.family)
        return disconnect(socket);
    if (socket->listening)
        return -106;
    if (socket->stream) {
        if (!socket->connect_pending)
            return -106;
        int64_t result = tcp_connect_result(socket);
        return result == would_block ? -114 : int(result);
    }
    if (address.family != 2)
        return -97;
    uint32_t peer = __builtin_bswap32(address.address);
    if (!peer)
        peer = 0x7f000001;
    return connect_to(socket, tcp::Address::ipv4(peer), address.port, socket->index);
}

int tcp6_connect(InetSocket* socket, const Inet6Address& address) {
    if (!address.family)
        return disconnect(socket);
    if (socket->listening)
        return -106;
    if (socket->stream) {
        if (!socket->connect_pending)
            return -106;
        int64_t result = tcp_connect_result(socket);
        return result == would_block ? -114 : int(result);
    }
    if (address.family != 10)
        return -97;
    if (address.address.mapped()) {
        if (socket->v6only || (socket->bound && socket->wire6))
            return -101;
        bool previous = socket->wire6;
        socket->wire6 = false;
        InetAddress mapped{
            2, address.port, __builtin_bswap32(tcp::Address::ipv6(address.address).ipv4()), {}};
        int error = tcp_connect(socket, mapped);
        if (error != -115)
            socket->wire6 = previous;
        return error;
    }
    if (socket->bind_completed && !socket->wire6)
        return -97;
    ip6::Address peer = address.address;
    if (peer.unspecified())
        peer.bytes[15] = 1;
    unsigned index = socket->index;
    if (peer.link_local()) {
        if (index && address.scope && index != address.scope)
            return -22;
        if (address.scope)
            index = address.scope;
        if (!index)
            return -22;
        if (index != ipv6_loopback && !net_info(index))
            return -19;
    }
    return connect_to(socket, tcp::Address::ipv6(peer), address.port, index);
}

int64_t tcp_connect_result(InetSocket* socket) {
    if (!socket->stream)
        return -107;
    auto state = socket->stream->state();
    if (state == tcp::State::syn_sent || state == tcp::State::syn_received)
        return would_block;
    if (state == tcp::State::closed) {
        int error = tcp_error(socket, true);
        reset_connect(socket);
        return error ? -error : -103;
    }
    socket->connect_pending = false;
    return 0;
}

int tcp_listen(InetSocket* socket, int backlog) {
    if (socket->stream)
        return -22;
    if (!socket->local_port) {
        int error = inet_bind_port(socket, socket->local, 0);
        if (error)
            return error;
    }
    // First listen rechecks current sharing flags on every overlapping owner.
    // An existing listener already owns its port when updating the backlog.
    if (!socket->listening && inet_port_conflict(socket, socket->local, socket->local_port))
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
    uint16_t local_port = socket->local_port ? socket->local_port : socket->reported_port;
    InetAddress address{2,
                        uint16_t(peer ? socket->peer_port : __builtin_bswap16(local_port)),
                        __builtin_bswap32(peer ? socket->peer : socket->local),
                        {}};
    if (socket->ipv6) {
        Inet6Address address6;
        address6.port = address.port;
        address6.address = (peer ? socket->stream_peer() : socket->stream_local()).bytes;
        if (address6.address.link_local())
            address6.scope = socket->index;
        return address_out(task, &address6, sizeof(address6), pointer, length);
    }
    return address_out(task, &address, sizeof(address), pointer, length);
}

int64_t tcp_accept(Task& task, Handle* handle, uint64_t address, uint64_t length, unsigned flags,
                   int fd) {
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
    install_reserved_fd(*task.files, fd, opened);
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
    if (!stream) {
        int error = tcp_error(socket, true);
        return error ? -error : -107;
    }
    if (stream->available()) {
        size_t count = stream->read(data, length, peek, peek ? offset : 0);
        if (count || !length)
            return count;
    }
    if (int error = tcp_error(socket, true))
        return -error;
    if (stream->eof() || stream->state() == tcp::State::closed ||
        stream->state() == tcp::State::time_wait)
        return 0;
    return length ? -11 : 0;
}

static int write_error(InetSocket* socket) {
    if (int error = tcp_error(socket, true))
        return -error;
    if (!socket->stream || (socket->shutdown & 2) ||
        socket->stream->state() == tcp::State::closed ||
        socket->stream->state() == tcp::State::time_wait)
        return -32;
    if (!synchronized(socket))
        return -11;
    return 0;
}

int tcp_write_check(InetSocket* socket) {
    if (int error = write_error(socket))
        return error;
    return socket->stream->writable() ? 0 : -11;
}

int64_t tcp_write(InetSocket* socket, const void* data, size_t length, bool flush) {
    if (int error = write_error(socket))
        return error;
    if (!length)
        return 0;
    size_t count = socket->stream->write(data, length, now_ms());
    if (flush)
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
            else
                socket->user_mss = value;
        } else if (socket->user_mss &&
                   (!socket->stream || socket->stream->state() == tcp::State::closed))
            value = socket->user_mss;
        else
            value = socket->stream ? socket->stream->segment_size() : socket->mss_cache;
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

static void receive(unsigned index, const tcp::Address& source, const tcp::Address& destination,
                    const tcp::Segment& segment) {
    uint64_t now = now_ms();
    expire_time_wait(now);
    for (auto& record : time_waits)
        if (record.used && record.local == destination && record.peer == source &&
            (!record.binding_index || record.binding_index == index) &&
            record.local_port == segment.destination &&
            record.peer_port == __builtin_bswap16(segment.source)) {
            auto action = tcp::time_wait_input(record.state, segment, now);
            if (action == tcp::TimeWaitAction::remove)
                record.used = false;
            else if (action == tcp::TimeWaitAction::acknowledge)
                record.pending = true;
            return;
        }
    InetSocket* listener = nullptr;
    for (auto& socket : inet_sockets) {
        if (!socket.used || socket.type != 1 || socket.local_port != segment.destination ||
            (socket.index && socket.index != index))
            continue;
        if (socket.stream && socket.stream_local() == destination &&
            socket.stream_peer() == source &&
            socket.peer_port == __builtin_bswap16(segment.source)) {
            if (socket.listener && socket.stream->state() == tcp::State::syn_received)
                inherit_ip_controls(socket, *socket.listener);
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
        if (socket.listening && socket.binding(socket.local).accepts(destination, index) &&
            (!listener || (!socket.binding(socket.local).local.unspecified() &&
                           listener->binding(listener->local).local.unspecified())))
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
        child->ipv6 = listener->ipv6;
        child->v6only = listener->v6only;
        child->wire6 = !destination.is_ipv4();
        if (child->wire6) {
            child->local6 = destination.bytes;
            child->peer6 = source.bytes;
        } else {
            child->local = destination.ipv4();
            child->peer = source.ipv4();
        }
        child->local_port = segment.destination;
        child->peer_port = __builtin_bswap16(segment.source);
        child->index = listener->index;
        if (child->wire6 && !child->index &&
            (child->local6.link_local() || child->peer6.link_local()))
            child->index = index;
        child->receive_limit = listener->receive_limit;
        child->send_limit = listener->send_limit;
        child->reuse = listener->reuse;
        child->nodelay = listener->nodelay;
        child->user_timeout = listener->user_timeout;
        child->user_mss = listener->user_mss;
        child->mtu_policy = listener->mtu_policy;
        inherit_ip_controls(*child, *listener);
        uint32_t initial;
        if (sequence(child, initial, now) || make_stream(child, now)) {
            reclaim(child);
            return;
        }
        uint16_t limit = child->user_mss ? child->user_mss : 1460;
        uint32_t mtu;
        if (child->wire6) {
            Ipv6Path path;
            if (ipv6_path(child->local6, child->peer6, child->index, path)) {
                reclaim(child);
                return;
            }
            ipv6_destination_store(child->destination6, path, child->peer6);
            mtu = path.mtu;
        } else {
            if (ipv4_destination(child->destination, child->local, child->peer, child->index)) {
                reclaim(child);
                return;
            }
            mtu = child->destination.path.mtu;
        }
        unsigned overhead = child->wire6 ? 60 : 40;
        uint16_t mss = min(limit, uint16_t(mtu > overhead ? min(mtu - overhead, 1460u) : 1));
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
    unsigned reply_index = listener ? listener->index : 0;
    // Link-local identities retain the receiving zone without a bound listener.
    if (!reply_index && !source.is_ipv4() &&
        (source.bytes.link_local() || destination.bytes.link_local()))
        reply_index = index;
    emit(nullptr, reply_index, destination, source, reset, {});
}

void tcp_receive(unsigned index, uint32_t source, uint32_t destination, const void* data,
                 size_t size) {
    tcp::Segment segment;
    if (tcp::decode(source, destination, data, size, segment))
        receive(index, tcp::Address::ipv4(source), tcp::Address::ipv4(destination), segment);
}

void tcp_receive(unsigned index, const ip6::Address& source, const ip6::Address& destination,
                 const void* data, size_t size) {
    // Mapped addresses describe IPv4 wire tuples; they never enter on IPv6 wire.
    if (source.unspecified() || source.multicast() || source.mapped() || destination.multicast() ||
        destination.mapped())
        return;
    tcp::Segment segment;
    if (tcp::decode(source, destination, data, size, segment))
        receive(index, tcp::Address::ipv6(source), tcp::Address::ipv6(destination), segment);
}

void tcp_poll() {
    if (polling)
        return;
    polling = true;
    uint64_t now = now_ms();
    expire_time_wait(now);
    for (auto& socket : inet_sockets) {
        if (!socket.used || socket.type != 1 || !socket.stream)
            continue;
        if (socket.index && socket.index != ipv4_loopback) {
            auto info = net_info(socket.index);
            if (!info || !info->live)
                tcp_failed(&socket, 5);
        }
        if (socket.listener && socket.stream->state() == tcp::State::syn_received)
            inherit_ip_controls(socket, *socket.listener);
        if (socket.wire6)
            tcp6_path_mtu(&socket);
        tcp::Segment segment;
        bool pending = socket.stream->next(now, segment);
        for (unsigned at = 0; pending && at < 4; at++) {
            segment.source = socket.local_port;
            segment.destination = __builtin_bswap16(socket.peer_port);
            int error = emit(&socket, socket.index, socket.stream_local(), socket.stream_peer(),
                             segment, header_options(socket));
            // A temporary queue, interface or route failure rejects this enqueue.
            // TCP retains its bytes and owns the local retry and delivery deadlines.
            if (error == -11 || error == -12 || error == -105 || error == -100 || error == -101) {
                socket.stream->output_blocked(now);
                break;
            }
            if (error == -90 && socket.wire6 && tcp6_path_mtu(&socket, 60 + segment.length)) {
                pending = socket.stream->next(now, segment);
                continue;
            }
            if (error) {
                tcp_failed(&socket, -error);
                pending = false;
                break;
            }
            socket.stream->emitted(now);
            pending = socket.stream->next(now, segment);
        }
        if (!pending && socket.connect_pending && socket.stream->state() == tcp::State::closed)
            release_automatic_port(&socket);
        if (!pending && socket.detached && socket.stream->state() == tcp::State::time_wait)
            compact_time_wait(&socket);
        else if (!pending && socket.stream->state() == tcp::State::closed &&
                 (socket.detached || (socket.listener && !socket.accept_queued)))
            reclaim(&socket);
    }
    for (auto& record : time_waits) {
        if (!record.used || !record.pending)
            continue;
        tcp::Segment segment{};
        segment.source = record.local_port;
        segment.destination = __builtin_bswap16(record.peer_port);
        segment.sequence = record.state.send;
        segment.acknowledgment = record.state.receive;
        segment.window = record.state.window;
        segment.flags = tcp::ack;
        HeaderOptions options;
        options.tos = options.traffic_class = record.traffic_class;
        int error =
            emit(nullptr, record.binding_index, record.local, record.peer, segment, options);
        if (!error || (error != -11 && error != -12 && error != -105))
            record.pending = false;
    }
    polling = false;
}
} // namespace ax
