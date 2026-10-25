// SPDX-License-Identifier: GPL-3.0-or-later
#include "net/inet.hpp"
#include "net/ipv4.hpp"
#include "net/ipv4_wire.hpp"
#include "net/udp.hpp"
#include "net/tcp/socket.hpp"
#include "process/task.hpp"
#include "socket.hpp"
#include "io/io.hpp"

namespace ax {
InetSocket inet_sockets[inet_socket_count];
static uint16_t next_port = 32768;
static uint64_t binding_order;

namespace {
struct DestinationRelease {
    InetSocket* socket;
    bool active;

    ~DestinationRelease() {
        if (active && socket->type != 1)
            ipv4_destination_release(socket->destination);
    }
};
} // namespace

Ipv4Destination* inet_output_destination(InetSocket* socket, uint32_t address, bool lookup_failed) {
    if (!socket || !socket->used || socket->peer != address)
        return nullptr;
    if (socket->type == 3 && (lookup_failed || !socket->destination.path.index))
        return nullptr;
    return &socket->destination;
}

bool inet_payload(InetSocket* socket) {
    return socket->type == 3 || socket->type == 2 || socket->type == 1;
}

InetSocket* inet_allocate(unsigned type) {
    for (auto& socket : inet_sockets)
        if (!socket.used) {
            socket = {};
            socket.used = true;
            socket.type = type;
            socket.protocol = type == 1 ? 6 : type == 2 ? 17 : 1;
            return &socket;
        }
    return nullptr;
}

static uint32_t network_address(uint32_t value) {
    return __builtin_bswap32(value);
}

const InetFrame* inet_front(InetSocket* socket) {
    return socket->count ? socket->queue[socket->head] : nullptr;
}

void inet_consume(InetSocket* socket) {
    if (!socket->count)
        return;
    auto& frame = socket->queue[socket->head];
    socket->bytes -= frame->length;
    release(frame);
    frame = nullptr;
    socket->head = (socket->head + 1) % inet_queue_count;
    socket->count--;
}

void inet_dispose(InetSocket* socket) {
    ipv4_detach_owner(socket);
    ipv6_detach_output(socket);
    while (socket->count)
        inet_consume(socket);
    socket->used = false;
}

void inet_close(InetSocket* socket) {
    if (inet_stream(socket))
        tcp_close(socket);
    else
        inet_dispose(socket);
}

InetAddress inet_peer(InetSocket* socket) {
    return {2, socket->peer_port, network_address(socket->peer), {}};
}

int inet_target(InetSocket* socket, InetAddress& address, bool named) {
    if (address.family != 2 && !(socket->type == 2 && address.family == 0))
        return -97;
    if (socket->type == 2 && named) {
        if (!address.port)
            return -22;
        if (!address.address)
            address.address = network_address(0x7f000001);
    }
    return address.address ? 0 : -89;
}

unsigned inet_shutdown(InetSocket* socket) {
    if (inet_stream(socket))
        return tcp_shutdown_state(socket);
    return socket->shutdown;
}

bool inet_port_conflict(InetSocket* socket, uint32_t local, uint16_t port) {
    if (socket->type == 1) {
        const auto binding = socket->binding(local);
        if (tcp_port_busy(binding, port, socket->reuse))
            return true;
        for (auto& other : inet_sockets)
            if (other.used && &other != socket && other.type == 1 && other.local_port == port &&
                binding.overlaps(other.binding(other.local)) &&
                (!socket->reuse || !other.reuse || other.listening))
                return true;
        return false;
    }
    for (auto& other : inet_sockets)
        if (other.used && &other != socket && other.type == socket->type &&
            other.local_port == port &&
            (!socket->index || !other.index || socket->index == other.index) &&
            (!local || !other.local || local == other.local) &&
            (!socket->reuse || !other.reuse || (socket->type == 1 && other.listening)))
            return true;
    return false;
}

int inet_bind_port(InetSocket* socket, uint32_t local, uint16_t port) {
    if (port) {
        if (inet_port_conflict(socket, local, port))
            return -98;
    } else {
        // Include completed TCP tuples as well as every live socket. One more
        // candidate than the maximum number of owners guarantees a free port.
        unsigned attempts = inet_socket_count + (socket->type == 1 ? tcp_time_wait_count : 0);
        for (unsigned attempt = 0; attempt < attempts; attempt++) {
            uint16_t candidate = next_port;
            next_port = next_port == 60999 ? 32768 : next_port + 1;
            if (!inet_port_conflict(socket, local, candidate)) {
                port = candidate;
                break;
            }
        }
        if (!port)
            return -11;
    }
    socket->local_port = port;
    socket->order = ++binding_order;
    return 0;
}

size_t inet_available(InetSocket* socket) {
    if (inet_stream(socket))
        return tcp_available(socket);
    auto frame = inet_front(socket);
    return frame ? frame->length : 0;
}

int inet_error(InetSocket* socket, bool clear) {
    if (inet_stream(socket))
        return tcp_error(socket, clear);
    if (socket->index && socket->index != ipv4_loopback) {
        const auto info = net_info(socket->index);
        if (!info || !info->live)
            return 5;
    }
    int error = socket->error;
    if (clear)
        socket->error = 0;
    return error;
}

void inet_failed(InetSocket* socket, int error, unsigned failed_index) {
    if (socket && socket->used && inet_stream(socket)) {
        tcp_failed(socket, error, failed_index);
        return;
    }
    if (socket && socket->used && !socket->error)
        socket->error = error;
}

void inet_icmp_error(unsigned index, const uint8_t* quote, int error, uint16_t announced_mtu) {
    uint32_t local = ip4::get32(quote + 12), peer = ip4::get32(quote + 16);
    InetSocket* best = nullptr;
    unsigned best_score = 0;
    for (auto& socket : inet_sockets) {
        if (!socket.used || (socket.peer && socket.peer != peer) ||
            (socket.index && socket.index != index) || (socket.local && socket.local != local))
            continue;
        if (socket.type == 3 && quote[9] == 1) {
            if (error == 90 && inet_accept_path_mtu(&socket)) {
                uint32_t learned =
                    ipv4_learn_pmtu(local, peer, index, announced_mtu, ip4::get16(quote + 2));
                if (learned && socket.peer)
                    ipv4_destination(socket.destination, socket.local, socket.peer, socket.index);
            }
            if (socket.peer && (error != 90 || socket.mtu_policy))
                inet_failed(&socket, error);
        }
        if (socket.type != 2 || quote[9] != 17 || socket.local_port != ip4::get16(quote + 20) ||
            (socket.peer_port && __builtin_bswap16(socket.peer_port) != ip4::get16(quote + 22)))
            continue;
        unsigned score = (socket.peer_port ? 4 : 0) + (socket.index ? 4 : 0);
        if (!best || score > best_score || (score == best_score && socket.order > best->order)) {
            best = &socket;
            best_score = score;
        }
    }
    if (best) {
        if (error == 90 && inet_accept_path_mtu(best)) {
            uint32_t learned =
                ipv4_learn_pmtu(local, peer, index, announced_mtu, ip4::get16(quote + 2));
            if (learned && best->peer)
                ipv4_destination(best->destination, best->local, best->peer, best->index);
        }
        if (best->peer && (error != 90 || best->mtu_policy))
            inet_failed(best, error);
    }
}

void inet_reclaim(InetSocket* socket, size_t length) {
    socket->transmitted -= min(socket->transmitted, length);
}

bool inet_dont_fragment(const InetSocket* socket, bool path_locked) {
    return !socket || socket->mtu_policy == 2 || socket->mtu_policy == 3 ||
           (socket->mtu_policy == 1 && !path_locked);
}

bool inet_fragmentation_allowed(const InetSocket* socket) {
    return !socket || socket->mtu_policy < 2 || socket->mtu_policy == 5;
}

bool inet_use_path_mtu(const InetSocket* socket) {
    return !socket || socket->mtu_policy < 3;
}

bool inet_accept_path_mtu(const InetSocket* socket) {
    return socket && socket->mtu_policy != 4 && socket->mtu_policy != 5;
}

bool inet_ready(InetSocket* socket, bool write) {
    if (inet_stream(socket))
        return tcp_ready(socket, write);
    return !inet_payload(socket) || inet_error(socket) ||
           (write ? (socket->shutdown & 2) ||
                        (ipv4_output_ready() && socket->transmitted < socket->send_limit)
                  : (socket->shutdown & 1) || socket->count != 0);
}

static void enqueue(InetSocket& socket, uint32_t source, uint16_t port, const void* data,
                    size_t length) {
    if (socket.count == inet_queue_count ||
        length > socket.receive_limit - min(socket.bytes, size_t(socket.receive_limit)))
        return;
    auto frame = static_cast<InetFrame*>(alloc(sizeof(InetFrame) + length));
    if (!frame)
        return;
    *frame = {{2, __builtin_bswap16(port), network_address(source), {}}, length};
    memcpy(frame + 1, data, length);
    socket.queue[(socket.head + socket.count) % inet_queue_count] = frame;
    socket.count++;
    socket.bytes += length;
}

void inet_deliver(unsigned index, uint32_t source, uint32_t destination, uint8_t protocol,
                  const void* data, size_t length) {
    if (protocol != 1 || length < 28)
        return;
    auto bytes = static_cast<const uint8_t*>(data);
    for (auto& socket : inet_sockets) {
        if (!socket.used || socket.type != 3 || (socket.index && socket.index != index) ||
            (socket.local && socket.local != destination) ||
            (socket.peer && socket.peer != source) ||
            (bytes[20] < 32 && (socket.filter & (uint32_t(1) << bytes[20]))))
            continue;
        enqueue(socket, source, 0, data, length);
    }
}

bool inet_datagram_deliver(unsigned index, uint32_t source, uint32_t destination,
                           uint16_t source_port, uint16_t destination_port, bool broadcast,
                           const void* data, size_t length) {
    InetSocket* best = nullptr;
    unsigned best_score = 0;
    bool matched = false;
    for (auto& socket : inet_sockets) {
        if (!socket.used || socket.type != 2 || !socket.local_port ||
            socket.local_port != destination_port || (socket.index && socket.index != index) ||
            (socket.local && socket.local != destination) ||
            (socket.peer && socket.peer != source) ||
            (socket.peer_port && __builtin_bswap16(socket.peer_port) != source_port))
            continue;
        matched = true;
        if (broadcast) {
            enqueue(socket, source, source_port, data, length);
            continue;
        }
        unsigned score = (socket.local ? 4 : 0) + (socket.peer ? 4 : 0) +
                         (socket.peer_port ? 4 : 0) + (socket.index ? 4 : 0);
        if (!best || score > best_score || (score == best_score && socket.order > best->order)) {
            best = &socket;
            best_score = score;
        }
    }
    if (best)
        enqueue(*best, source, source_port, data, length);
    return matched;
}

int64_t inet_send(InetSocket* socket, const InetAddress& address, const void* data, size_t length,
                  bool named) {
    if (inet_stream(socket))
        return tcp_write(socket, data, length);
    if (!inet_payload(socket))
        return -95;
    if (int error = inet_error(socket, true))
        return -error;
    if (socket->shutdown & 2)
        return -32;
    uint32_t destination = network_address(address.address);
    if (!destination)
        return -89;
    size_t overhead = socket->type == 2 ? 28 : 20;
    if (length > 65535 - overhead || length + overhead > socket->send_limit)
        return -90;
    if (length + overhead >
        socket->send_limit - min(socket->transmitted, size_t(socket->send_limit)))
        return -11;
    Ipv4Source source{socket->local};
    bool connected = !named && destination == socket->peer;
    if (socket->type == 2 && connected) {
        if (ipv4_destination_current(socket->destination))
            source = Ipv4Source::retained(socket->local);
        int routed = ipv4_destination(socket->destination, source, destination, socket->index);
        if (routed)
            return routed == -99 ? -101 : routed;
    }
    int error;
    if (socket->type == 2) {
        if (!socket->local_port) {
            error = inet_bind_port(socket, socket->local, 0);
            if (error)
                return error;
        }
        UdpOutput output{source,
                         destination,
                         socket->index,
                         socket->local_port,
                         __builtin_bswap16(address.port),
                         socket->ttl,
                         socket->broadcast,
                         connected};
        error = udp_send(socket, output, data, length);
        if (connected && socket->destination.path.index)
            socket->destination.source = socket->local;
        if (error == -99)
            error = -101;
    } else
        error = ipv4_send(socket, socket->local, destination, socket->index, 1, socket->ttl,
                          socket->broadcast, data, length);
    if (!error)
        socket->transmitted += length + overhead;
    return error ? error : int64_t(length);
}

int64_t inet_read(InetSocket* socket, void* data, size_t length) {
    if (inet_stream(socket))
        return tcp_read(socket, data, length);
    if (!inet_payload(socket))
        return -95;
    if (int error = inet_error(socket, true))
        return -error;
    auto frame = inet_front(socket);
    if (!frame)
        return -11;
    size_t copied = min(length, frame->length);
    memcpy(data, inet_bytes(frame), copied);
    inet_consume(socket);
    return copied;
}

static int address_in(Task& task, uint64_t pointer, uint64_t length, InetAddress& address) {
    if (length < sizeof(InetAddress))
        return -22;
    if (!task.memory->space.copy_in(&address, pointer, sizeof(address)))
        return -14;
    return address.family == 2 ? 0 : -97;
}

static int address_out(Task& task, const InetAddress& address, uint64_t pointer,
                       uint64_t length_pointer) {
    uint32_t length, actual = sizeof(address);
    if (!task.memory->space.copy_in(&length, length_pointer, 4) ||
        !task.memory->space.copy_out(pointer, &address, min(length, actual)) ||
        !task.memory->space.copy_out(length_pointer, &actual, 4))
        return -14;
    return 0;
}

int64_t inet_syscall(Task& task, const Frame& frame) {
    auto a = frame.rdi, b = frame.rsi, c = frame.rdx, d = frame.r10;
    auto handle = a < max_fds ? task.files->entries[a].handle : nullptr;
    auto socket = handle ? handle->inet : nullptr;
    if (frame.rax == 41) {
        if (b & ~uint64_t(0x8080f))
            return -22;
        const unsigned type = b & 0xf;
        if (type == 3 && !capable(task.credentials, Capability::net_raw))
            return -1;
        if (!((type == 3 && c == 1) || (type == 2 && (c == 0 || c == 17)) ||
              (type == 1 && (c == 0 || c == 6))))
            return -93;
        socket = inet_allocate(type);
        if (!socket)
            return -23;
        auto opened = open_handle(nullptr, 2 | ((b & 0x800) ? 04000 : 0));
        if (!opened) {
            inet_close(socket);
            return -23;
        }
        opened->inet = socket;
        int fd = allocate_fd(&task, opened, 0, b & 0x80000);
        if (fd < 0)
            close_handle(opened);
        return fd;
    }
    if (!socket)
        return -88;
    if (tcp_ipv6(socket)) {
        if (frame.rax == 42 || frame.rax == 49 || frame.rax == 51 || frame.rax == 52 ||
            ((frame.rax == 54 || frame.rax == 55) && b == 41))
            return tcp6_syscall(task, frame);
    }
    if (inet_stream(socket)) {
        if (frame.rax == 42)
            return io_syscall(task, frame);
        if (frame.rax == 48)
            return tcp_shutdown(socket, unsigned(b));
        if (frame.rax == 50)
            return tcp_listen(socket, int32_t(b));
        if (frame.rax == 51 || frame.rax == 52)
            return tcp_address(task, socket, frame.rax == 52, b, c);
    }
    switch (frame.rax) {
    case 42:
    case 49: {
        if (!inet_payload(socket))
            return -95;
        InetAddress address;
        if (frame.rax == 42 && c >= 2) {
            uint16_t family;
            if (!task.memory->space.copy_in(&family, b, 2))
                return -14;
            if (!family) { // AF_UNSPEC disconnect
                socket->destination = {};
                socket->peer = 0;
                socket->peer_port = 0;
                if (!socket->bound)
                    socket->local = 0;
                if (socket->type == 2) {
                    if (!socket->port_locked)
                        socket->local_port = 0;
                    socket->error = 0;
                    socket->order = ++binding_order;
                }
                return 0;
            }
        }
        int error = address_in(task, b, c, address);
        if (error)
            return error;
        uint32_t value = network_address(address.address);
        if (frame.rax == 49) {
            if ((socket->type == 2 || socket->type == 1) && (socket->local_port || socket->peer))
                return -22;
            if (value && !ipv4_local(value))
                return -99;
            if (socket->type == 2 || socket->type == 1) {
                unsigned port = __builtin_bswap16(address.port);
                if (port && port < 1024 && !capable(task.credentials, Capability::net_bind_service))
                    return -13;
                error = inet_bind_port(socket, value, __builtin_bswap16(address.port));
                if (error)
                    return error;
                socket->port_locked = address.port != 0;
            }
            socket->local = value;
            socket->bound = value != 0;
            socket->destination = {};
        } else {
            if (!value) {
                if (socket->type == 3)
                    return -22;
                value = 0x7f000001;
            }
            Ipv4Destination destination;
            error = ipv4_destination(destination, socket->bound ? socket->local : 0, value,
                                     socket->index);
            if (error)
                return error;
            uint32_t selected = destination.path.source;
            destination.source = selected;
            if (socket->type == 2 && !socket->local_port) {
                error = inet_bind_port(socket, socket->bound ? socket->local : 0, 0);
                if (error)
                    return error;
            }
            if (socket->type == 2 && socket->local != selected)
                socket->order = ++binding_order;
            socket->local = selected;
            socket->peer = value;
            socket->peer_port = address.port;
            socket->destination = destination;
        }
        return 0;
    }
    case 48:
        if (socket->type != 2)
            return -95;
        if (b > 2)
            return -22;
        socket->shutdown |= b == 0 ? 1 : b == 1 ? 2 : 3;
        return socket->peer ? 0 : -107;
    case 51:
    case 52: {
        bool peer = frame.rax == 52;
        if (peer && (!socket->peer || !socket->peer_port))
            return -107;
        InetAddress address{2,
                            uint16_t(peer                ? socket->peer_port
                                     : socket->type == 3 ? 0x0100
                                                         : __builtin_bswap16(socket->local_port)),
                            network_address(peer ? socket->peer : socket->local),
                            {}};
        return address_out(task, address, b, c);
    }
    case 54: {
        if (b == 1 && c == 25) { // SO_BINDTODEVICE
            if (frame.r8 > 16)
                return -22;
            char name[17]{};
            if (!task.memory->space.copy_in(name, d, frame.r8))
                return -14;
            unsigned index = 0;
            if (name[0]) {
                if (!strcmp(name, "lo"))
                    index = ipv4_loopback;
                for (unsigned i = 1; auto info = net_info(i); i++)
                    if (!strcmp(name, info->name))
                        index = i;
                if (!index)
                    return -19;
            }
            socket->destination = {};
            socket->index = index;
            return 0;
        }
        int value;
        if (frame.r8 < 4)
            return -22;
        if (!task.memory->space.copy_in(&value, d, 4))
            return -14;
        DestinationRelease finish{socket, b == 1 || (b == 0 && c == 10)};
        if (b == 6 && inet_stream(socket)) {
            int error;
            return tcp_option(socket, unsigned(c), value, true, error) ? error : -92;
        }
        if (b == 1 && c == 2 && (socket->type == 2 || socket->type == 1))
            socket->reuse = value != 0;
        else if (b == 1 && c == 6)
            socket->broadcast = value != 0;
        else if (b == 1 && (c == 7 || c == 8 || c == 32)) {
            if (c == 32 && !capable(task.credentials, Capability::net_admin))
                return -1;
            if (value < 0 && c != 32)
                return -22;
            uint64_t limit = c == 32 ? uint64_t(INT32_MAX / 2) * 2 : uint64_t(inet_queue_bytes);
            uint32_t bound = uint32_t(min(uint64_t(max(value, 0)) * 2, limit));
            bound = max(bound, uint32_t(2048));
            (c == 8 ? socket->receive_limit : socket->send_limit) = bound;
            if (inet_stream(socket))
                tcp_limits(socket);
        } else if (b == 0 && c == 2) {
            if (value < 1 || value > 255)
                return -22;
            socket->ttl = value;
        } else if (b == 0 && c == 10) {
            if (value < 0 || value > 5)
                return -22;
            socket->mtu_policy = value;
        } else if (b == 255 && c == 1 && socket->type == 3)
            socket->filter = uint32_t(value);
        else
            return -92;
        return 0;
    }
    case 55: {
        uint32_t value = 0, length, actual = 4;
        if (!task.memory->space.copy_in(&length, frame.r8, 4))
            return -14;
        if (int32_t(length) < 0)
            return -22;
        DestinationRelease finish{socket, b == 0 && (c == 10 || c == 14)};
        if (b == 1) {
            if (c == 2 && (socket->type == 2 || socket->type == 1))
                value = socket->reuse;
            else if (c == 3)
                value = socket->type;
            else if (c == 4)
                value = inet_stream(socket) ? tcp_so_error(socket, false) : inet_error(socket);
            else if (c == 6)
                value = socket->broadcast;
            else if (c == 7)
                value = socket->send_limit;
            else if (c == 8)
                value = socket->receive_limit;
            else if (c == 30 && inet_stream(socket))
                value = socket->listening;
            else if (c == 38)
                value = socket->protocol;
            else if (c == 39)
                value = tcp_ipv6(socket) ? 10 : 2;
            else
                return -92;
        } else if (b == 6 && inet_stream(socket)) {
            int option_value = 0, error;
            if (!tcp_option(socket, unsigned(c), option_value, false, error))
                return -92;
            if (error)
                return error;
            value = option_value;
        } else if (b == 0 && c == 2)
            value = socket->ttl;
        else if (b == 0 && c == 10)
            value = socket->mtu_policy;
        else if (b == 0 && c == 14) {
            int mtu = ipv4_destination_mtu(socket->destination, false);
            if (mtu < 0)
                return mtu;
            value = uint32_t(mtu);
        } else if (b == 255 && c == 1 && socket->type == 3)
            value = socket->filter;
        else
            return -92;
        if (!task.memory->space.copy_out(d, &value, min(length, actual)) ||
            !task.memory->space.copy_out(frame.r8, &actual, 4))
            return -14;
        if (b == 1 && c == 4) {
            if (inet_stream(socket))
                tcp_so_error(socket, true);
            else
                inet_error(socket, true);
        }
        return 0;
    }
    default:
        return -95;
    }
}
} // namespace ax
