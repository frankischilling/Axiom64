// SPDX-License-Identifier: GPL-3.0-or-later
#include "ipc.hpp"

namespace ax {
static Socket sockets[256];
static Epoll* epolls[64];
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
    for (auto& socket : sockets)
        if (!socket.used) {
            socket = {};
            socket.used = true;
            socket.type = type;
            socket.capacity = 65536;
            socket.bytes = (uint8_t*)alloc(socket.capacity);
            if (!socket.bytes) {
                socket.used = false;
                return nullptr;
            }
            return &socket;
        }
    return nullptr;
}
void socket_close(Socket* s) {
    if (!s || !s->used)
        return;
    if (s->peer) {
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
    release(s->bytes);
    s->bytes = nullptr;
    s->used = false;
}
bool socket_ready(Socket* s, bool write) {
    if (s->listener)
        return !write && s->queue_size;
    if (write)
        return !s->peer || s->write_closed || s->peer->read_closed ||
               s->peer->size < s->peer->capacity;
    return s->size || s->peer_closed || s->read_closed || !s->connected ||
           (s->peer && s->peer->write_closed);
}
int64_t socket_read(Socket* s, void* data, size_t len, bool peek) {
    if (s->listener || !s->connected)
        return -107;
    if (!len || s->read_closed)
        return 0;
    if (!s->size)
        return s->peer_closed || !s->peer || s->peer->write_closed ? 0 : -11;
    len = min(len, s->size);
    auto output = (uint8_t*)data;
    for (size_t i = 0; i < len; i++)
        output[i] = s->bytes[(s->head + i) % s->capacity];
    if (!peek) {
        s->head = (s->head + len) % s->capacity;
        s->size -= len;
    }
    return len;
}
int64_t socket_write(Socket* s, const void* data, size_t len) {
    if (!s->connected)
        return -107;
    if (s->write_closed || !s->peer || s->peer->read_closed)
        return -32;
    if (!len)
        return 0;
    auto peer = s->peer;
    if (peer->size == peer->capacity)
        return -11;
    len = min(len, peer->capacity - peer->size);
    auto input = (const uint8_t*)data;
    for (size_t i = 0; i < len; i++)
        peer->bytes[(peer->head + peer->size + i) % peer->capacity] = input[i];
    peer->size += len;
    return len;
}
static Handle* handle(int fd) {
    return fd >= 0 && unsigned(fd) < max_fds ? current->fds[fd].handle : nullptr;
}
static int install_socket(Socket* socket, int flags = 0) {
    Handle* h = open_handle(nullptr, 2 | (flags & 04000));
    if (!h) {
        if (!socket->pending)
            socket_close(socket);
        return -23;
    }
    h->socket = socket;
    int fd = allocate_fd(current, h, 0, flags & 02000000);
    if (fd < 0) {
        h->socket = nullptr;
        close_handle(h);
        if (!socket->pending)
            socket_close(socket);
    }
    return fd;
}
struct UnixAddress {
    uint16_t family;
    uint8_t path[108];
};
static int address(uint64_t pointer, size_t length, UnixAddress& result, size_t& path_length) {
    if (length < 2 || length > sizeof(result))
        return -22;
    result = {};
    if (!current->memory.copy_in(&result, pointer, length))
        return -14;
    if (result.family != 1)
        return -97;
    path_length = length - 2;
    if (!path_length)
        return -22;
    if (result.path[0]) {
        if (path_length == 108 && result.path[107])
            return -36;
        result.path[min(path_length, size_t(107))] = 0;
        path_length = strlen((const char*)result.path) + 1;
    }
    return 0;
}
static int output_address(Socket* s, uint64_t pointer, uint64_t length_pointer) {
    if (!pointer && !length_pointer)
        return 0;
    uint32_t size;
    if (!current->memory.copy_in(&size, length_pointer, 4))
        return -14;
    UnixAddress address{};
    address.family = 1;
    memcpy(address.path, s->local, s->local_length);
    uint32_t actual = 2 + s->local_length;
    if (!current->memory.copy_out(pointer, &address, min(size, actual)) ||
        !current->memory.copy_out(length_pointer, &actual, 4))
        return -14;
    return 0;
}
static int64_t blocked(int fd, bool write = false) {
    current->state = State::blocked;
    current->wait = write ? Wait::write : Wait::read;
    current->wait_fd = fd;
    return would_block;
}
static int64_t transfer(int fd, uint64_t buffer, size_t length, bool write, unsigned flags = 0) {
    auto h = handle(fd);
    if (!h || !h->socket)
        return -88;
    if (flags & ~unsigned(2 | 0x40 | 0x100 | 0x4000))
        return -95;
    if (!current->memory.valid(buffer, length, !write))
        return -14;
    uint8_t data[4096];
    size_t done = 0;
    while (done < length) {
        size_t count = min(length - done, sizeof(data));
        if (write)
            current->memory.copy_in(data, buffer + done, count);
        int64_t n = write ? socket_write(h->socket, data, count)
                          : socket_read(h->socket, data, count, flags & 2);
        if (n < 0) {
            if (done)
                return done;
            if (n == -11 && !(h->flags & 04000) && !(flags & 0x40))
                return blocked(fd, write);
            return n;
        }
        if (!write)
            current->memory.copy_out(buffer + done, data, n);
        done += n;
        if (size_t(n) < count || (flags & 2) || (!write && !socket_ready(h->socket, false)))
            break;
    }
    return done;
}
uint32_t readiness(Handle* h) {
    if (!h)
        return 32;
    uint32_t events = 0;
    if (handle_ready(h, false))
        events |= 1;
    if (handle_ready(h, true))
        events |= 4;
    if (h->pipe && !h->writer && !h->pipe->writers)
        events |= 16;
    if (h->socket && !h->socket->listener &&
        (h->socket->peer_closed || (h->socket->peer && h->socket->peer->write_closed)))
        events |= 16 | 0x2000;
    return events;
}
static int epoll_events(Task& task, Epoll* poll, uint64_t output, unsigned count, bool copy) {
    unsigned ready = 0;
    for (auto& item : poll->items) {
        if (!item.used || !item.enabled || item.fd < 0 || unsigned(item.fd) >= max_fds ||
            task.fds[item.fd].handle != item.handle || item.handle->generation != item.generation)
            continue;
        uint32_t mask = (item.event.events & (1u << 31))
                            ? item.pending
                            : readiness(item.handle) & (item.event.events | 8 | 16);
        if (!mask)
            continue;
        if (copy) {
            EpollEvent event{mask, item.event.data};
            if (!task.memory.copy_out(output + ready * sizeof(event), &event, sizeof(event)))
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
void epoll_notify() {
    for (auto poll : epolls)
        if (poll)
            for (auto& item : poll->items)
                if (item.used && item.enabled && item.handle->references &&
                    item.handle->generation == item.generation) {
                    uint32_t ready = readiness(item.handle) & (item.event.events | 8 | 16);
                    item.pending |= ready & ~item.last_ready;
                    item.last_ready = ready;
                }
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
        if (pointers[set] && bytes && !task.memory.copy_in(input[set], pointers[set], bytes))
            return -14;
    int ready = 0;
    for (int fd = 0; fd < count; fd++) {
        uint64_t bit = 1ull << (fd % 64);
        for (unsigned set = 0; set < 3; set++)
            if (input[set][fd / 64] & bit) {
                auto h = unsigned(fd) < max_fds ? task.fds[fd].handle : nullptr;
                if (!h)
                    return -9;
                uint32_t wanted = set == 0 ? 1 | 8 | 16 : set == 1 ? 4 | 8 | 16 : 2;
                if (readiness(h) & wanted) {
                    output[set][fd / 64] |= bit;
                    ready++;
                }
            }
    }
    if (copy)
        for (unsigned set = 0; set < 3; set++)
            if (pointers[set] && bytes && !task.memory.copy_out(pointers[set], output[set], bytes))
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
        auto h = fd >= 0 && unsigned(fd) < max_fds ? task.fds[fd].handle : nullptr;
        return !h || !h->epoll || epoll_events(task, h->epoll, 0, max_fds, false) != 0;
    }
    struct Pollfd {
        int32_t fd;
        int16_t events, revents;
    };
    for (size_t i = 0; i < task.frame.rsi && i < max_fds; i++) {
        Pollfd p;
        if (!task.memory.copy_in(&p, task.frame.rdi + i * sizeof(p), sizeof(p)))
            return true;
        if (p.fd < 0)
            continue;
        auto h = unsigned(p.fd) < max_fds ? task.fds[p.fd].handle : nullptr;
        if (readiness(h) & (p.events | 8 | 16 | 32))
            return true;
    }
    return false;
}
struct Message {
    uint64_t name;
    uint32_t name_length, padding;
    uint64_t iov, iov_count, control, control_length;
    uint32_t flags, padding2;
};
struct Iovec {
    uint64_t base, length;
};
int64_t ipc_syscall(Frame* f) {
    auto a = f->rdi, b = f->rsi, c = f->rdx, d = f->r10;
    auto h = handle(a);
    Socket* s = h ? h->socket : nullptr;
    switch (f->rax) {
    case 41: {
        if (a != 1)
            return -97;
        if ((b & 0xf) != 1 || (b & ~uint64_t(0x8080f)) || c)
            return -93;
        s = allocate_socket();
        return s ? install_socket(s, ((b & 0x800) ? 04000 : 0) | ((b & 0x80000) ? 02000000 : 0))
                 : -12;
    }
    case 49: {
        if (!s)
            return -88;
        if (s->local_length)
            return -22;
        UnixAddress addr;
        size_t len;
        int error = address(b, c, addr, len);
        if (error)
            return error;
        for (auto& other : sockets)
            if (!addr.path[0] && other.used && other.local_length == len &&
                !memcmp(other.local, addr.path, len))
                return -98;
        if (addr.path[0]) {
            Path path;
            path.base = current->cwd_node;
            memcpy(path.text, addr.path, len);
            if (lookup(path, false))
                return -98;
            error = create_node(path, 0140000 | 0777, s->bound_node);
            if (error)
                return error;
        }
        memcpy(s->local, addr.path, len);
        s->local_length = len;
        return 0;
    }
    case 50:
        if (!s)
            return -88;
        if (!s->local_length || s->connected)
            return -22;
        s->listener = true;
        s->backlog = min(max(size_t(b), size_t(1)), size_t(32));
        return 0;
    case 42: {
        if (!s)
            return -88;
        if (s->connected)
            return -106;
        UnixAddress addr;
        size_t len;
        int error = address(b, c, addr, len);
        if (error)
            return error;
        Socket* listener = nullptr;
        Node* target = nullptr;
        if (addr.path[0]) {
            Path path;
            path.base = current->cwd_node;
            memcpy(path.text, addr.path, len);
            error = resolve_path(path, target);
            if (error)
                return error;
        }
        for (auto& other : sockets)
            if (other.used && other.listener &&
                (addr.path[0] ? other.bound_node == target :
                 other.local_length == len && !memcmp(other.local, addr.path, len)))
                listener = &other;
        if (!listener)
            return -111;
        if (listener->queue_size >= listener->backlog)
            return -11;
        auto server = allocate_socket();
        if (!server)
            return -12;
        server->connected = true;
        server->pending = true;
        server->peer = s;
        server->local_length = listener->local_length;
        server->bound_node = listener->bound_node;
        memcpy(server->local, listener->local, listener->local_length);
        s->peer = server;
        s->connected = true;
        listener->queue[(listener->queue_head + listener->queue_size) % 32] = server;
        listener->queue_size++;
        return 0;
    }
    case 43:
    case 288: {
        if (!s)
            return -88;
        if (!s->listener)
            return -22;
        if (!s->queue_size)
            return (h->flags & 04000) ? -11 : blocked(a);
        if (f->rax == 288 && (d & ~uint64_t(0x80800)))
            return -22;
        auto accepted = s->queue[s->queue_head];
        if (b) {
            int error = output_address(accepted->peer ? accepted->peer : accepted, b, c);
            if (error)
                return error;
        }
        int flags = f->rax == 288 ? ((d & 0x800) ? 04000 : 0) | ((d & 0x80000) ? 02000000 : 0) : 0;
        int fd = install_socket(accepted, flags);
        if (fd < 0)
            return fd;
        accepted->pending = false;
        s->queue_head = (s->queue_head + 1) % 32;
        s->queue_size--;
        return fd;
    }
    case 44:
        if (f->r8)
            return -106;
        return transfer(a, b, c, true, d);
    case 45: {
        int64_t n = transfer(a, b, c, false, d);
        if (n >= 0 && f->r8 && s) {
            int result = output_address(s->peer ? s->peer : s, f->r8, f->r9);
            if (result)
                return result;
        }
        return n;
    }
    case 46:
    case 47: {
        if (!s)
            return -88;
        Message message;
        if (!current->memory.copy_in(&message, b, sizeof(message)))
            return -14;
        if (message.iov_count > 1024)
            return -22;
        if (message.control_length && f->rax == 46)
            return -95;
        size_t done = 0;
        for (size_t i = 0; i < message.iov_count; i++) {
            Iovec v;
            if (!current->memory.copy_in(&v, message.iov + i * sizeof(v), sizeof(v)))
                return done ? int64_t(done) : -14;
            if (done && !socket_ready(s, f->rax == 46))
                break;
            auto n = transfer(a, v.base, v.length, f->rax == 46, c);
            if (n < 0)
                return done ? int64_t(done) : n;
            done += n;
            if (uint64_t(n) < v.length)
                break;
        }
        if (f->rax == 47) {
            message.control_length = 0;
            message.flags = 0;
            if (!current->memory.copy_out(b, &message, sizeof(message)))
                return -14;
        }
        return done;
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
        return output_address(s, b, c);
    case 52:
        if (!s)
            return -88;
        if (!s->connected || !s->peer)
            return -107;
        return output_address(s->peer, b, c);
    case 53: {
        if (a != 1 || (b & 0xf) != 1 || c)
            return -95;
        if (!current->memory.valid(d, 8, true))
            return -14;
        auto left = allocate_socket(), right = allocate_socket();
        if (!left || !right) {
            socket_close(left);
            socket_close(right);
            return -12;
        }
        left->peer = right;
        right->peer = left;
        left->connected = right->connected = true;
        int flags = ((b & 0x800) ? 04000 : 0) | ((b & 0x80000) ? 02000000 : 0);
        int result[2] = {install_socket(left, flags), -1};
        if (result[0] >= 0)
            result[1] = install_socket(right, flags);
        if (result[0] < 0 || result[1] < 0) {
            if (result[0] >= 0) {
                close_handle(current->fds[result[0]].handle);
                current->fds[result[0]] = {};
            } else
                socket_close(right);
            return -24;
        }
        current->memory.copy_out(d, result, 8);
        return 0;
    }
    case 54:
        if (!s)
            return -88;
        if (b != 1)
            return -92;
        if (c == 2 || c == 9 || c == 7 || c == 8)
            return current->memory.valid(d, f->r8) ? 0 : -14;
        return -92;
    case 55: {
        if (!s)
            return -88;
        if (b != 1)
            return -92;
        int value = c == 3 ? s->type : c == 4 ? 0 : c == 7 || c == 8 ? int(s->capacity) : -1;
        if (value < 0)
            return -92;
        uint32_t len;
        if (!current->memory.copy_in(&len, f->r8, 4))
            return -14;
        uint32_t actual = 4;
        if (!current->memory.copy_out(d, &value, min(len, actual)) ||
            !current->memory.copy_out(f->r8, &actual, 4))
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
        if (!current->memory.copy_in(&event, d, sizeof(event)))
            return -14;
        if (!item)
            for (auto& candidate : h->epoll->items)
                if (!candidate.used) {
                    item = &candidate;
                    break;
                }
        if (!item)
            return -28;
        *item = {target, target->generation, int(c), event, true, true, 0, 0};
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
