// SPDX-License-Identifier: GPL-3.0-or-later
#include "ipc/ipc.hpp"
#include "fs/inotify.hpp"
#include "ipc/timerfd.hpp"
#include "socket_registry.hpp"
#include "fs/descriptor.hpp"
#include "io/socket_timeout.hpp"
#include "net/tcp/socket.hpp"
#include "net/packet.hpp"
#include "net/inet.hpp"
#include "net/inet6.hpp"
#include "net/netlink.hpp"

namespace ax {
Socket sockets[256];
static Epoll* epolls[64];
static uint64_t next_signal_wait_queue = 1;

bool socket_node_busy(Node* node) {
    for (auto& socket : sockets)
        if (socket.used && file_node(socket.bound_node) == node)
            return true;
    return false;
}

bool socket_mount_busy(Mount* mount) {
    for (auto& socket : sockets)
        if (socket.used && socket.bound_node && socket.bound_node->mount == mount)
            return true;
    return false;
}

static Socket* allocate_socket(unsigned type = 1) {
    static uint64_t next_generation = 1;
    if (next_generation == UINT64_MAX)
        return nullptr;
    for (auto& socket : sockets)
        if (!socket.used) {
            socket = {};
            socket.used = true;
            socket.credentials = {current->process->pid, current->credentials.user.effective,
                                  current->credentials.group.effective};
            socket.type = type;
            if (type == 2 && !(socket.datagram_send = UnixSendBudget::create())) {
                socket.used = false;
                return nullptr;
            }
            if (!(socket.local_name = UnixAddressName::create({}))) {
                if (socket.datagram_send)
                    socket.datagram_send->close();
                socket.datagram_send = nullptr;
                socket.used = false;
                return nullptr;
            }
            socket.generation = next_generation++;
            return &socket;
        }
    return nullptr;
}

void socket_close(Socket* s) {
    if (!s || !s->used)
        return;
    if (s->type == 2) {
        for (auto& other : sockets)
            if (&other != s && other.used && other.type == 2 && other.peer == s &&
                other.peer_generation == s->generation) {
                other.peer = nullptr;
                other.peer_closed = true;
            }
    } else if (s->peer) {
        s->peer->peer = nullptr;
        s->peer->peer_closed = true;
    }
    while (s->queue_size) {
        Socket* queued = s->queue[s->queue_head];
        s->queue_head = (s->queue_head + 1) % 32;
        s->queue_size--;
        queued->pending = false;
        socket_close(queued);
    }
    s->stream.clear();
    s->datagrams.clear();
    if (s->local_name)
        s->local_name->drop();
    s->local_name = nullptr;
    if (s->peer_name)
        s->peer_name->drop();
    s->peer_name = nullptr;
    if (s->datagram_send)
        s->datagram_send->close();
    s->datagram_send = nullptr;
    s->description = nullptr;
    s->used = false;
}

bool socket_ready(Socket* s, bool write) {
    if (s->type == 2)
        return write ? socket_datagram_writable(*s) : s->read_closed || s->datagrams.readable();
    if (s->listener)
        return !write && (s->queue_size || s->read_closed);
    if (write)
        return !s->peer || s->write_closed || s->peer->read_closed ||
               s->peer->stream.size() < UnixStreamQueue::capacity;
    return s->stream.size() || s->peer_closed || s->read_closed ||
           (s->peer && s->peer->write_closed);
}

int64_t socket_read(Socket* s, void* data, size_t len, bool peek, size_t peek_offset) {
    if (s->type == 2) {
        if (!len)
            return 0;
        const uint8_t* bytes;
        size_t length;
        if (!s->datagrams.front(bytes, length))
            return s->read_closed ? 0 : -11;
        len = min(len, length);
        if (len)
            memcpy(data, bytes, len);
        if (!peek)
            s->datagrams.consume();
        return len;
    }
    if (s->type != 1)
        return -95;
    if (s->listener || !s->connected)
        return -107;
    if (!len || s->read_closed)
        return 0;
    size_t offset = peek ? peek_offset : 0;
    if (offset >= s->stream.size())
        return s->peer_closed || !s->peer || s->peer->write_closed ? 0 : -11;
    size_t copied = 0;
    auto record = s->stream.front();
    while (record && offset >= record->size()) {
        offset -= record->size();
        record = record->next();
    }
    while (record && copied < len) {
        size_t count = min(len - copied, record->size() - offset);
        memcpy(static_cast<uint8_t*>(data) + copied, record->data() + offset, count);
        bool boundary = record->rights();
        auto next = record->next();
        if (!peek) {
            UnixRights* rights = nullptr;
            s->stream.consume(count, rights);
            if (rights)
                rights->drop();
        }
        copied += count;
        if (boundary)
            break;
        record = next;
        offset = 0;
    }
    return copied;
}

int64_t socket_write(Socket* s, const void* data, size_t len, uint32_t datagram_entry_limit) {
    if (s->type == 2) {
        if (s->pass_credentials)
            if (int error = socket_unix_autobind(*s))
                return error;
        int error;
        auto record = UnixDatagramRecord::create(*s->datagram_send, len, error,
                                                 datagram_entry_limit, s->local_name);
        if (!record)
            return error;
        if (len)
            memcpy(record->data(), data, len);
        UnixDatagramTarget target;
        int64_t result = socket_datagram_write(*current, s, record, nullptr, target);
        if (result < 0)
            record->drop();
        return result;
    }
    if (s->type != 1)
        return -95;
    if (!s->connected)
        return -107;
    if (s->write_closed || !s->peer || s->peer->read_closed)
        return -32;
    if (!len)
        return 0;
    auto peer = s->peer;
    if (peer->stream.size() == UnixStreamQueue::capacity)
        return -11;
    len = min(len, UnixStreamQueue::capacity - peer->stream.size());
    auto record = UnixStreamRecord::create(len);
    if (!record)
        return -12;
    memcpy(record->data(), data, len);
    UnixMessageCredentials identity;
    if (s->pass_credentials || peer->pass_credentials)
        identity.capture(*current);
    UnixRights* rights = nullptr;
    peer->stream.accept(record, len, identity, rights, peer, s->local_name);
    return len;
}

static Handle* handle(int fd) {
    auto h = fd >= 0 && unsigned(fd) < max_fds ? current->files->entries[fd].handle : nullptr;
    return h && (h->flags & 010000000) ? nullptr : h;
}

static int install_socket(Task& task, Socket* socket, int flags = 0, int reserved = -1) {
    Handle* h = open_handle(nullptr, 2 | (flags & 04000));
    if (!h) {
        if (!socket->pending)
            socket_close(socket);
        return -23;
    }
    h->socket = socket;
    int fd = reserved;
    if (fd >= 0)
        install_reserved_fd(*task.files, fd, h);
    else
        fd = allocate_fd(&task, h, 0, flags & 02000000);
    if (fd < 0) {
        h->socket = nullptr;
        close_handle(h);
        if (!socket->pending)
            socket_close(socket);
    } else
        socket->description = h;
    return fd;
}

int socket_output_address(Task& task, Socket* s, uint64_t pointer, uint64_t length_pointer) {
    return socket_unix_output_name(task, s->local_name, pointer, length_pointer);
}

int64_t socket_accept(Task& task, Handle* h, uint64_t address, uint64_t length, unsigned flags,
                      int reserved) {
    auto s = h->socket;
    if (!s->listener)
        return -22;
    if (!s->queue_size)
        return (h->flags & 04000) ? -11 : s->read_closed ? -22 : would_block;
    auto accepted = s->queue[s->queue_head];
    int fd = address ? socket_unix_output_name(task, accepted->peer_name, address, length) : 0;
    if (!fd) {
        fd = install_socket(task, accepted,
                            ((flags & 0x800) ? 04000 : 0) | ((flags & 0x80000) ? 02000000 : 0),
                            reserved);
        if (fd < 0)
            return fd;
    }
    accepted->pending = false;
    accepted->accepting = nullptr;
    s->queue_head = (s->queue_head + 1) % 32;
    s->queue_size--;
    if (fd < 0)
        socket_close(accepted);
    return fd;
}

uint32_t readiness(Handle* h, const Task* task) {
    if (!h)
        return 32;
    // select uses the default mask for a path description; poll rejects it.
    if (h->flags & 010000000)
        return 1 | 4;
    uint32_t events = 0;
    if (auto pipe = h->pipe) {
        unsigned mode = h->flags & 3;
        if (mode != 1) {
            if (pipe->size)
                events |= 1 | 0x40; // POLLIN | POLLRDNORM
            if (!pipe->writers && h->pipe_hangup_generation != pipe->writer_generation)
                events |= 16; // POLLHUP
        }
        if (mode != 0) {
            if (pipe->size < sizeof(pipe->bytes))
                events |= 4 | 0x100; // POLLOUT | POLLWRNORM
            if (!pipe->readers)
                events |= 8; // POLLERR
        }
        return events;
    }
    if (handle_ready(h, false, task))
        events |= h->inotify ? inotify_read_events : 1;
    if (handle_ready(h, true, task))
        events |= 4;
    if (h->packet) {
        auto info = net_info(packet_interface(h->packet));
        if (info && !info->live)
            events |= 8;
    }
    if (h->inet) {
        if (inet_stream(h->inet))
            return tcp_events(h->inet);
        unsigned shutdown = inet_shutdown(h->inet);
        if (!inet_front(h->inet) && !(shutdown & 1))
            events &= ~1u;
        if (inet_error(h->inet))
            events |= 8;
        if (shutdown & 1)
            events |= 0x2000;
        if (shutdown == 3)
            events |= 16;
    }
    if (h->inet6) {
        unsigned shutdown = inet6_shutdown(h->inet6);
        if (!inet6_front(h->inet6) && !(shutdown & 1))
            events &= ~1u;
        if (inet6_error(h->inet6) || inet6_error_queued(h->inet6))
            events |= 8;
        if (shutdown & 1)
            events |= 0x2000;
        if (shutdown == 3)
            events |= 16;
    }
    if (h->socket && h->socket->type == 1) {
        auto socket = h->socket;
        bool read_closed = socket->read_closed || socket->peer_closed ||
                           (socket->peer && socket->peer->write_closed);
        bool write_closed = socket->write_closed || socket->peer_closed ||
                            (socket->peer && socket->peer->read_closed);
        if (read_closed)
            events |= 0x2000;
        if ((read_closed && write_closed) || (!socket->connected && !socket->listener))
            events |= 16;
    }
    if (h->socket && h->socket->type == 2) {
        if (h->socket->datagram_error)
            events |= 8;
        if (h->socket->read_closed)
            events |= 0x2000;
        if (h->socket->read_closed && h->socket->write_closed)
            events |= 16;
    }
    return events;
}

static void epoll_timer_event(EpollItem& item, uint32_t ready) {
    if (auto timer = item.handle->timer) {
        uint64_t notification = timerfd_notification(*timer);
        if (notification != item.timer_notification) {
            item.pending |= ready & 1;
            item.timer_notification = notification;
        }
    }
}

static int epoll_events(Task& task, Epoll* poll, uint64_t output, unsigned count, bool copy) {
    unsigned ready = 0;
    for (auto& item : poll->items) {
        if (!item.used || !item.enabled || !item.handle->references ||
            item.handle->generation != item.generation)
            continue;
        if (!item.signal_wait_queue && (item.fd < 0 || unsigned(item.fd) >= max_fds ||
                                        task.files->entries[item.fd].handle != item.handle))
            continue;
        uint32_t ready_now = readiness(item.handle, &task) & (item.event.events | 8 | 16);
        epoll_timer_event(item, ready_now);
        // A queued edge can become stale before this waiter gets to consume it.
        item.pending &= ready_now;
        // A signal descriptor waits on the registering task's signal handlers.
        // A ready signal in a different process does not queue an epoll event.
        bool edge_triggered = item.event.events & (1u << 31);
        uint32_t mask = item.signal_wait_queue            ? item.pending
                        : edge_triggered && !item.pending ? 0
                                                          : ready_now;
        if (!mask)
            continue;
        if (copy) {
            EpollEvent event{mask, item.event.data};
            if (!task.memory->space.copy_out(output + ready * sizeof(event), &event, sizeof(event)))
                return -14;
            if (item.event.events & (1u << 31))
                item.pending = 0;
            if (item.event.events & (1u << 30))
                item.enabled = false;
        }
        if (++ready == count)
            break;
    }
    return ready;
}

void epoll_notify(Handle* source, uint32_t events) {
    for (auto poll : epolls)
        if (poll)
            for (auto& item : poll->items)
                if (item.used && item.enabled && !item.signal_wait_queue &&
                    item.handle->references && item.handle->generation == item.generation) {
                    uint32_t ready = readiness(item.handle, nullptr) & (item.event.events | 8 | 16);
                    if (item.handle->timer)
                        epoll_timer_event(item, ready);
                    else
                        item.pending |= ready & ~item.last_ready;
                    if (item.handle == source ||
                        (source && source->pipe && item.handle->pipe == source->pipe))
                        item.pending |= ready & events;
                    item.last_ready = ready;
                }
}

void epoll_signal_notify(const SignalHandlers& handlers) {
    if (!handlers.descriptor_wait_queue)
        return;
    for (auto poll : epolls)
        if (poll)
            for (auto& item : poll->items)
                if (item.used && item.enabled &&
                    item.signal_wait_queue == handlers.descriptor_wait_queue &&
                    item.handle->references && item.handle->generation == item.generation)
                    item.pending |= item.event.events & 1;
}

void epoll_close(Epoll* poll) {
    for (auto& entry : epolls)
        if (entry == poll)
            entry = nullptr;
    release(poll);
}

int select_events(Task& task, const Frame& frame, bool copy) {
    int count = int(frame.rdi);
    if (count < 0 || count > 1024)
        return -22;
    uint64_t input[3][16]{}, output[3][16]{};
    uint64_t pointers[] = {frame.rsi, frame.rdx, frame.r10};
    size_t bytes = ((count + 63) / 64) * 8;
    for (unsigned set = 0; set < 3; set++)
        if (pointers[set] && bytes && !task.memory->space.copy_in(input[set], pointers[set], bytes))
            return -14;
    int ready = 0;
    for (int fd = 0; fd < count; fd++) {
        uint64_t bit = 1ull << (fd % 64);
        for (unsigned set = 0; set < 3; set++)
            if (input[set][fd / 64] & bit) {
                auto h = unsigned(fd) < max_fds ? task.files->entries[fd].handle : nullptr;
                if (!h)
                    return -9;
                uint32_t wanted = set == 0 ? 1 | 8 | 16 : set == 1 ? 4 | 8 : 2;
                if (readiness(h, &task) & wanted) {
                    output[set][fd / 64] |= bit;
                    ready++;
                }
            }
    }
    if (copy)
        for (unsigned set = 0; set < 3; set++)
            if (pointers[set] && bytes &&
                !task.memory->space.copy_out(pointers[set], output[set], bytes))
                return -14;
    return ready;
}

bool poll_task_ready(Task& task) {
    if (task.deadline && ticks >= task.deadline)
        return true;
    if (task.frame.rax == 23 || task.frame.rax == 270)
        return select_events(task, task.frame, false) != 0;
    if (task.frame.rax == 232 || task.frame.rax == 281) {
        int fd = task.frame.rdi;
        auto h = fd >= 0 && unsigned(fd) < max_fds ? task.files->entries[fd].handle : nullptr;
        return !h || !h->epoll || epoll_events(task, h->epoll, 0, max_fds, false) != 0;
    }

    struct Pollfd {
        int32_t fd;
        int16_t events, revents;
    };

    for (size_t i = 0; i < task.frame.rsi && i < max_fds; i++) {
        Pollfd p;
        if (!task.memory->space.copy_in(&p, task.frame.rdi + i * sizeof(p), sizeof(p)))
            return true;
        if (p.fd < 0)
            continue;
        auto h = unsigned(p.fd) < max_fds ? task.files->entries[p.fd].handle : nullptr;
        if (h && (h->flags & 010000000))
            return true;
        if (readiness(h, &task) & (p.events | 8 | 16 | 32))
            return true;
    }
    return false;
}

int64_t ipc_syscall(Frame* f) {
    auto a = f->rdi, b = f->rsi, c = f->rdx, d = f->r10;
    auto h = handle(a);
    if (!h && (f->rax == 42 || f->rax == 48 || f->rax == 49 || f->rax == 50 || f->rax == 51 ||
               f->rax == 52 || f->rax == 54 || f->rax == 55))
        return -9;
    Socket* s = h ? h->socket : nullptr;
    int64_t timeout_result;
    if (socket_timeout_syscall(*current, *f, h, timeout_result))
        return timeout_result;
    if ((f->rax == 41 && a == 16) ||
        (h && h->netlink &&
         (f->rax == 42 || f->rax == 48 || f->rax == 49 || f->rax == 50 || f->rax == 51 ||
          f->rax == 52 || f->rax == 54 || f->rax == 55)))
        return netlink_syscall(*current, *f);
    if (s && (s->type == 1 || s->type == 2) && f->rax == 49)
        return socket_unix_bind(*current, *s, b, c);
    if (s && s->type == 2 && f->rax == 42)
        return socket_datagram_connect(*current, *s, b, uint32_t(c));
    if (s && s->type != 1 && (f->rax == 42 || f->rax == 49 || f->rax == 50))
        return -95;
    if ((f->rax == 41 && a == 2) ||
        (h && h->inet &&
         (f->rax == 42 || f->rax == 48 || f->rax == 49 || f->rax == 50 || f->rax == 51 ||
          f->rax == 52 || f->rax == 54 || f->rax == 55)))
        return inet_syscall(*current, *f);
    if ((f->rax == 41 && a == 10) ||
        (h && h->inet6 &&
         (f->rax == 42 || f->rax == 48 || f->rax == 49 || f->rax == 50 || f->rax == 51 ||
          f->rax == 52 || f->rax == 54 || f->rax == 55)))
        return inet6_syscall(*current, *f);
    if ((f->rax == 41 && a == 17) ||
        (h && h->packet &&
         (f->rax == 42 || f->rax == 48 || f->rax == 49 || f->rax == 50 || f->rax == 51 ||
          f->rax == 52 || f->rax == 54 || f->rax == 55)))
        return packet_syscall(*current, *f);
    switch (f->rax) {
    case 41: {
        if (a != 1)
            return -97;
        if (((b & 0xf) != 1 && (b & 0xf) != 2) || (b & ~uint64_t(0x8080f)) || c)
            return -93;
        // libc also uses unbound Unix datagram descriptors for interface ioctls.
        // Named datagram endpoints remain separate from socketpair data queues.
        s = allocate_socket(b & 0xf);
        return s ? install_socket(*current, s,
                                  ((b & 0x800) ? 04000 : 0) | ((b & 0x80000) ? 02000000 : 0))
                 : -12;
    }
    case 49:
        return -88;
    case 50:
        if (!s)
            return -88;
        if (!s->local_name->address().length || s->connected)
            return -22;
        s->listener = true;
        s->credentials = {current->process->pid, current->credentials.user.effective,
                          current->credentials.group.effective};
        s->backlog = min(max(size_t(b), size_t(1)), size_t(32));
        return 0;
    case 42: {
        if (!s)
            return -88;
        if (s->connected)
            return -106;
        UnixAddressValue addr;
        int error = socket_unix_address(*current, b, uint32_t(c), addr);
        if (error)
            return error;
        if (s->pass_credentials)
            if ((error = socket_unix_autobind(*s)))
                return error;
        Socket* listener = nullptr;
        Node* target = nullptr;
        if (!addr.abstract()) {
            Path path;
            path.base = current->fs->cwd_node;
            memcpy(path.text, addr.path, addr.length);
            error = resolve_path(path, target);
            if (error)
                return error;
            if ((error = node_access(target, 2)))
                return error;
            target = file_node(target);
        }
        for (auto& other : sockets)
            if (other.used && other.type == 1 && other.listener &&
                (!addr.abstract() ? file_node(other.bound_node) == target
                                  : other.local_name->address().same(addr)))
                listener = &other;
        if (!listener || listener->read_closed)
            return -111;
        if (listener->queue_size >= listener->backlog)
            return -11;
        auto server = allocate_socket();
        if (!server)
            return -12;
        server->connected = true;
        server->peer_credentials = {current->process->pid, current->credentials.user.effective,
                                    current->credentials.group.effective};
        s->peer_credentials = listener->credentials;
        server->pending = true;
        server->accepting = listener;
        server->pass_credentials = listener->pass_credentials;
        server->peer = s;
        server->peer_generation = s->generation;
        // The accepted socket keeps the pathname's mount busy after listener close.
        server->bound_node = listener->bound_node;
        server->local_name->drop();
        server->local_name = listener->local_name;
        server->local_name->retain();
        server->peer_name = s->local_name;
        server->peer_name->retain();
        s->peer = server;
        s->peer_generation = server->generation;
        s->peer_name = server->local_name;
        s->peer_name->retain();
        s->connected = true;
        listener->queue[(listener->queue_head + listener->queue_size) % 32] = server;
        listener->queue_size++;
        return 0;
    }
    case 48:
        if (!s)
            return -88;
        if (b > 2)
            return -22;
        if (b == 0 || b == 2)
            s->read_closed = true;
        if (b == 1 || b == 2)
            s->write_closed = true;
        return 0;
    case 51:
        if (!s)
            return -88;
        return socket_output_address(*current, s, b, c);
    case 52:
        if (!s)
            return -88;
        if (!s->connected)
            return -107;
        return socket_unix_output_name(*current, s->peer_name, b, c);
    case 53: {
        if (a != 1 || ((b & 0xf) != 1 && (b & 0xf) != 2) || c || (b & ~uint64_t(0x8080f)))
            return -95;
        if (!current->memory->space.valid(d, 8, true))
            return -14;
        auto left = allocate_socket(b & 0xf), right = allocate_socket(b & 0xf);
        if (!left || !right) {
            socket_close(left);
            socket_close(right);
            return -12;
        }
        left->peer = right;
        right->peer = left;
        left->peer_generation = right->generation;
        right->peer_generation = left->generation;
        left->peer_name = right->local_name;
        right->peer_name = left->local_name;
        left->peer_name->retain();
        right->peer_name->retain();
        left->connected = right->connected = true;
        left->peer_credentials = right->credentials;
        right->peer_credentials = left->credentials;
        int flags = ((b & 0x800) ? 04000 : 0) | ((b & 0x80000) ? 02000000 : 0);
        int result[2] = {install_socket(*current, left, flags), -1};
        if (result[0] >= 0)
            result[1] = install_socket(*current, right, flags);
        if (result[0] < 0 || result[1] < 0) {
            if (result[0] >= 0) {
                close_handle(current->files->entries[result[0]].handle);
                current->files->entries[result[0]] = {};
            } else
                socket_close(right);
            return -24;
        }
        current->memory->space.copy_out(d, result, 8);
        return 0;
    }
    case 54:
        if (!s)
            return -88;
        if (b != 1)
            return -92;
        if (c == 16) {
            if (int32_t(f->r8) < int32_t(sizeof(int)))
                return -22;
            int value;
            if (!current->memory->space.copy_in(&value, d, sizeof(value)))
                return -14;
            s->pass_credentials = value != 0;
            return 0;
        }
        if (s->type == 2 && (c == 7 || c == 8)) {
            if (f->r8 < sizeof(uint32_t))
                return -22;
            uint32_t value;
            if (!current->memory->space.copy_in(&value, d, sizeof(value)))
                return -14;
            if (c == 7)
                s->datagram_send->resize(value);
            else
                s->datagram_receive = unix_buffer_size(value, false);
            return 0;
        }
        if (c == 2 || c == 9 || c == 7 || c == 8)
            return current->memory->space.valid(d, f->r8) ? 0 : -14;
        return -92;
    case 55: {
        if (!s)
            return -88;
        if (b != 1)
            return -92;
        if (c == 16) {
            uint32_t length;
            if (!current->memory->space.copy_in(&length, f->r8, 4))
                return -14;
            if (int32_t(length) < 0)
                return -22;
            length = min(length, uint32_t(sizeof(int)));
            int value = s->pass_credentials;
            if (!current->memory->space.copy_out(d, &value, length) ||
                !current->memory->space.copy_out(f->r8, &length, 4))
                return -14;
            return 0;
        }
        if (c == 17) {
            uint32_t length;
            if (!current->memory->space.copy_in(&length, f->r8, 4))
                return -14;
            length = min(length, uint32_t(sizeof(PeerCredentials)));
            if (!current->memory->space.copy_out(d, &s->peer_credentials, length) ||
                !current->memory->space.copy_out(f->r8, &length, 4))
                return -14;
            return 0;
        }
        int value = c == 3             ? s->type
                    : c == 4           ? 0
                    : c == 7 || c == 8 ? int(UnixStreamQueue::capacity)
                                       : -1;
        if (s->type == 2 && (c == 7 || c == 8))
            value = c == 7 ? s->datagram_send->size() : s->datagram_receive;
        if (value < 0)
            return -92;
        uint32_t len;
        if (!current->memory->space.copy_in(&len, f->r8, 4))
            return -14;
        if (s->type == 2 && c == 4) {
            value = s->datagram_error;
            s->datagram_error = 0;
        }
        uint32_t actual = 4;
        if (!current->memory->space.copy_out(d, &value, min(len, actual)) ||
            !current->memory->space.copy_out(f->r8, &actual, 4))
            return -14;
        return 0;
    }
    case 213:
    case 291: {
        if ((f->rax == 213 && !a) || (f->rax == 291 && (a & ~uint64_t(02000000))))
            return -22;
        auto poll = (Epoll*)alloc(sizeof(Epoll));
        if (!poll)
            return -12;
        bool registered = false;
        for (auto& entry : epolls)
            if (!entry) {
                entry = poll;
                registered = true;
                break;
            }
        if (!registered) {
            release(poll);
            return -23;
        }
        auto fd = open_handle(nullptr, 2);
        if (!fd) {
            epoll_close(poll);
            return -23;
        }
        fd->epoll = poll;
        int n = allocate_fd(current, fd, 0, f->rax == 291 && (a & 02000000));
        if (n < 0)
            close_handle(fd);
        return n;
    }
    case 233: {
        if (!h || !h->epoll)
            return -9;
        auto target = handle(c);
        if (!target || target == h)
            return -9;
        EpollItem* item = nullptr;
        for (auto& existing : h->epoll->items)
            if (existing.used && existing.fd == int(c) && existing.handle == target &&
                existing.generation == target->generation)
                item = &existing;
        if (b == 2) {
            if (!item)
                return -2;
            item->used = false;
            return 0;
        }
        if (b == 1 && item)
            return -17;
        if (b == 3 && !item)
            return -2;
        if (b != 1 && b != 3)
            return -22;
        EpollEvent event;
        if (!current->memory->space.copy_in(&event, d, sizeof(event)))
            return -14;
        if (!item)
            for (auto& candidate : h->epoll->items)
                if (!candidate.used || !candidate.handle->references ||
                    candidate.handle->generation != candidate.generation) {
                    item = &candidate;
                    break;
                }
        if (!item)
            return -28;
        uint64_t wait_queue = 0;
        uint32_t pending = 0;
        if (target->signal_descriptor) {
            auto& handler_queue = current->handlers->descriptor_wait_queue;
            if (b == 1 && !handler_queue)
                handler_queue = next_signal_wait_queue++;
            wait_queue = b == 1 ? handler_queue : item->signal_wait_queue;
            pending = readiness(target, current) & event.events & 1;
        }
        *item = {target, target->generation, int(c), event, true, true, 0, pending, 0, wait_queue};
        epoll_notify();
        return 0;
    }
    case 232:
    case 281: {
        if (!h || !h->epoll)
            return -9;
        if (int32_t(c) <= 0 || uint32_t(c) > 0x7fffffffu / sizeof(EpollEvent))
            return -22;
        if (b >= user_limit || uint64_t(uint32_t(c)) * sizeof(EpollEvent) > user_limit - b)
            return -14;
        int n = epoll_events(*current, h->epoll, b, c, true);
        if (n || int(d) == 0) {
            current->deadline = 0;
            return n;
        }
        if (current->deadline && ticks >= current->deadline) {
            current->deadline = 0;
            return 0;
        }
        if (int(d) > 0 && !current->deadline)
            current->deadline = ticks + (d + 9) / 10;
        current->state = State::blocked;
        current->wait = Wait::poll;
        return would_block;
    }
    default:
        return -38;
    }
}
} // namespace ax
