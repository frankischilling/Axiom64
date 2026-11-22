// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/ipc/ipc.cpp
 * @brief   Unix socket and epoll operations.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Dispatches local socket calls and manages epoll interest sets and readiness
 * delivery.
 *
 * Copyright (C) 2026 frankischilling
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://gnu.org/licenses/>.
 */
#include "ipc/ipc.hpp"
#include "io/descriptor_wait.hpp"
#include "fs/inotify.hpp"
#include "fs/pipe.hpp"
#include "fs/proc.hpp"
#include "ipc/timerfd.hpp"
#include "process/signals.hpp"
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
static constexpr unsigned max_epolls = 64;
static Epoll* epolls[max_epolls];
static EpollItem* exclusive_first;
static EpollItem* exclusive_last;
static uint64_t next_signal_wait_queue = 1;

static constexpr uint32_t read_events = 1 | 0x40;                     // POLLIN | POLLRDNORM
static constexpr uint32_t write_events = 4 | 0x100;                   // POLLOUT | POLLWRNORM
static constexpr uint32_t socket_write_events = write_events | 0x200; // Also POLLWRBAND.
static constexpr uint32_t stream_peer_close = read_events | socket_write_events | 16 | 0x2000;
static void epoll_notify_source(const void*, uint32_t);

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

static bool unix_socket_type(unsigned type) {
    return type == 1 || type == 2 || type == Socket::seqpacket_type;
}

static Socket* allocate_socket(unsigned type) {
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
            if (socket.uses_record_queue() && !(socket.datagram_send = UnixSendBudget::create())) {
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
                if (other.datagram_send->writable())
                    descriptor_wait_notify(&other, socket_write_events);
            }
    } else if (auto peer = s->peer) {
        peer->peer = nullptr;
        peer->peer_closed = true;
        descriptor_wait_notify(peer, stream_peer_close);
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
    node_reference_released(s->bound_node);
    s->bound_node = nullptr;
}

bool socket_ready(Socket* s, bool write) {
    if (s->listener)
        return !write && (s->queue_size || s->read_closed);
    if (s->uses_record_queue()) {
        bool ended = s->type == Socket::seqpacket_type ? s->receive_eof() : s->read_closed;
        return write ? socket_datagram_writable(*s) : ended || s->datagrams.readable();
    }
    if (write)
        return !s->peer || s->write_closed || s->peer->read_closed ||
               s->peer->stream.size() < UnixStreamQueue::capacity;
    return s->stream.size() || s->peer_closed || s->read_closed ||
           (s->peer && s->peer->write_closed);
}

void Socket::publish_stream(UnixStreamRecord* record, size_t length,
                            const UnixMessageCredentials& credentials, UnixRights*& rights,
                            UnixAddressName* sender) {
    stream.accept(record, length, credentials, rights, this, sender);
    epoll_notify_source(this, read_events);
}

void Socket::consume_stream(size_t length, UnixRights*& rights) {
    bool full = stream.size() == UnixStreamQueue::capacity;
    stream.consume(length, rights);
    if (full && peer)
        epoll_notify_source(peer, socket_write_events);
}

int64_t socket_read(Socket* s, void* data, size_t len, bool peek, size_t peek_offset) {
    if (s->uses_record_queue()) {
        bool sequenced = s->type == Socket::seqpacket_type;
        if (sequenced && !s->connected)
            return -107;
        if (!len)
            return 0;
        const uint8_t* bytes;
        size_t length;
        if (!s->datagrams.front(bytes, length))
            return (sequenced ? s->receive_eof() : s->read_closed) ? 0 : -11;
        socket_datagram_receive_wakeup(*s);
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
            s->consume_stream(count, rights);
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

int64_t socket_write(Task& task, Socket* s, const void* data, size_t len,
                     uint32_t datagram_entry_limit) {
    if (s->uses_record_queue()) {
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
        int64_t result = socket_datagram_write(task, s, record, nullptr, target);
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
        identity.capture(task);
    UnixRights* rights = nullptr;
    peer->publish_stream(record, len, identity, rights, s->local_name);
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

static bool epoll_readable(Epoll&, const Task*);
static void epoll_refresh(Epoll&, const void*, uint32_t, uint64_t&);
static void epoll_notify_exclusive(const void*, uint32_t, uint64_t signal_wait_queue = 0);
static constexpr uint32_t default_poll_mask = read_events | write_events;
static constexpr uint32_t epoll_exclusive = 1u << 28;
static constexpr uint32_t epoll_exclusive_events =
    epoll_exclusive | (1u << 29) | (1u << 31) | 1 | 4 | 8 | 16;

uint32_t readiness(Handle* h, const Task* task) {
    if (!h)
        return 32;
    // select uses the default mask for a path description; poll rejects it.
    if ((h->flags & 010000000) || !handle_has_poll(*h))
        return default_poll_mask;
    if (h->epoll)
        return epoll_readable(*h->epoll, task) ? read_events : 0;
    if (h->node && h->node->mount->ops == &procfs_ops)
        return default_poll_mask;
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
            if (!pipe->full())
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
    if (h->inet || h->inet6) {
        if (events & 1)
            events |= read_events;
        if (events & 4)
            events |= socket_write_events;
    }
    if (h->socket && h->socket->type != 2) {
        auto socket = h->socket;
        if (events & 1)
            events |= read_events;
        if (events & 4)
            events |= socket_write_events;
        bool read_closed = socket->receive_eof();
        bool write_closed = socket->write_closed || socket->peer_closed ||
                            (socket->peer && socket->peer->read_closed);
        if (read_closed)
            events |= 0x2000;
        if ((read_closed && write_closed) || (!socket->connected && !socket->listener))
            events |= 16;
    }
    if (h->socket && h->socket->type == 2) {
        if (events & 1)
            events |= read_events;
        if (events & 4)
            events |= socket_write_events;
        if (h->socket->datagram_error)
            events |= 8;
        if (h->socket->read_closed)
            events |= 0x2000;
        if (h->socket->read_closed && h->socket->write_closed)
            events |= 16;
    }
    return events;
}

static void epoll_append_exclusive(Epoll& epoll, EpollItem& item) {
    item.exclusive_owner = &epoll;
    item.exclusive_prev = exclusive_last;
    if (exclusive_last)
        exclusive_last->exclusive_next = &item;
    else
        exclusive_first = &item;
    exclusive_last = &item;
}

static void epoll_unlink_exclusive(EpollItem& item) {
    if (!item.exclusive_owner)
        return;
    if (auto previous = item.exclusive_prev)
        previous->exclusive_next = item.exclusive_next;
    else
        exclusive_first = item.exclusive_next;
    if (auto next = item.exclusive_next)
        next->exclusive_prev = item.exclusive_prev;
    else
        exclusive_last = item.exclusive_prev;
    item.exclusive_owner = nullptr;
    item.exclusive_prev = item.exclusive_next = nullptr;
}

struct EpollScan {
    const Task* task;
    uint64_t scanned = 0;
    uint64_t readable = 0;
};

static bool epoll_readable(Epoll&, EpollScan&);

static uint32_t epoll_item_events(EpollItem& item, EpollScan& scan) {
    if (!item.enabled || !item.live())
        return 0;
    auto child = item.handle->epoll;
    bool requires_notification =
        child || item.signal_wait_queue || (item.event.events & (epoll_exclusive | (1u << 31)));
    if (requires_notification && !item.pending)
        return 0;
    uint32_t ready;
    if (child)
        ready = epoll_readable(*child, scan) ? read_events : 0;
    else
        ready = readiness(item.handle, scan.task);
    ready &= item.event.events | 8 | 16;
    item.pending &= ready;
    // A signal watch is notified through the registering task's signal handlers.
    if (item.signal_wait_queue)
        return item.pending;
    if (requires_notification && !item.pending)
        return 0;
    return ready;
}

static bool epoll_readable(Epoll& epoll, EpollScan& scan) {
    const uint64_t bit = 1ull << epoll.index;
    if (!(scan.scanned & bit)) {
        scan.scanned |= bit;
        for (auto& item : epoll.items)
            if (epoll_item_events(item, scan)) {
                scan.readable |= bit;
                break;
            }
    }
    return scan.readable & bit;
}

static bool epoll_readable(Epoll& epoll, const Task* task) {
    uint64_t visited = 0;
    epoll_notify_exclusive(nullptr, 0);
    epoll_refresh(epoll, nullptr, 0, visited);
    EpollScan scan{task};
    return epoll_readable(epoll, scan);
}

static int epoll_events(Task& task, Epoll* poll, uint64_t output, unsigned count) {
    uint64_t visited = 0;
    epoll_notify_exclusive(nullptr, 0);
    epoll_refresh(*poll, nullptr, 0, visited);
    unsigned ready = 0, start = poll->cursor;
    EpollScan scan{&task};
    for (unsigned offset = 0; offset < max_fds; offset++) {
        unsigned index = (start + offset) % max_fds;
        auto& item = poll->items[index];
        // The fd is part of the registration key. Delivery follows the live description.
        uint32_t mask = epoll_item_events(item, scan);
        if (!mask)
            continue;
        EpollEvent event{mask, item.event.data};
        if (!task.memory->space.copy_out(output + ready * sizeof(event), &event, sizeof(event)))
            return ready ? int(ready) : -14;
        if (item.event.events & (1u << 31))
            item.pending = 0;
        if (item.event.events & (1u << 30))
            item.enabled = false;
        poll->cursor = (index + 1) % max_fds;
        if (++ready == count)
            break;
    }
    return ready;
}

static void epoll_restore_mask(Task& task) {
    if (!task.suspend_mask)
        return;
    task.signal_mask = task.suspend_saved_mask;
    task.suspend_mask = false;
}

static int64_t epoll_wait(Task& task, Handle* handle, const Frame& frame) {
    const bool uses_timespec = frame.rax == 441;
    const int32_t milliseconds = int32_t(frame.r10);
    const bool finite = uses_timespec ? frame.r10 != 0 : milliseconds >= 0;
    uint64_t delay = 0;
    if (finite) {
        if (uses_timespec) {
            struct Timeout {
                int64_t seconds, nanoseconds;
            } timeout;

            if (!task.memory->space.copy_in(&timeout, frame.r10, sizeof(timeout)))
                return -14;
            if (timeout.seconds < 0 || timeout.nanoseconds < 0 || timeout.nanoseconds >= 1000000000)
                return -22;
            // The scheduler measures waits in 10 ms units. Round a fraction up
            // and keep enormous relative timeouts from wrapping to a short wait.
            uint64_t fraction = (uint64_t(timeout.nanoseconds) + 9999999) / 10000000;
            uint64_t seconds = uint64_t(timeout.seconds);
            delay = seconds > (UINT64_MAX - fraction) / 100 ? UINT64_MAX : seconds * 100 + fraction;
        } else {
            delay = (uint64_t(milliseconds) + 9) / 10;
        }
    }

    bool temporary_mask = frame.rax != 232 && frame.r8;
    uint64_t mask = 0;
    if (temporary_mask) {
        if (frame.r9 != sizeof(mask))
            return -22;
        if (!task.memory->space.copy_in(&mask, frame.r8, sizeof(mask)))
            return -14;
    }
    if (!handle)
        return -9;
    unsigned maximum = uint32_t(frame.rdx);
    if (!maximum || maximum > INT32_MAX / sizeof(EpollEvent))
        return -22;
    uint64_t events = frame.rsi;
    if (events >= user_limit || uint64_t(maximum) * sizeof(EpollEvent) > user_limit - events)
        return -14;
    if (!handle->epoll)
        return -22;

    if (temporary_mask) {
        task.suspend_saved_mask = task.signal_mask;
        task.suspend_mask = true;
        task.signal_mask = mask & ~unmaskable_signals;
    }
    int ready = epoll_events(task, handle->epoll, events, maximum);
    if (ready || (finite && !delay)) {
        epoll_restore_mask(task);
        return ready;
    }
    retain(handle);
    task.epoll_wait_handle = handle;
    task.deadline = finite ? ticks + min(delay, UINT64_MAX - ticks) : 0;
    task.state = State::blocked;
    task.wait = Wait::epoll_wait;
    return would_block;
}

void epoll_discard_wait(Task& task) {
    auto handle = task.epoll_wait_handle;
    if (!handle)
        return;
    task.epoll_wait_handle = nullptr;
    close_handle(handle);
}

bool epoll_resume_wait(Task& task) {
    if (task.wait != Wait::epoll_wait)
        return false;
    auto handle = task.epoll_wait_handle;
    int result = epoll_events(task, handle->epoll, task.frame.rsi, unsigned(task.frame.rdx));
    if (!result && (!task.deadline || ticks < task.deadline))
        return false;
    task.frame.rax = result;
    task.frame.rip += 2;
    task.deadline = 0;
    task.wait = Wait::none;
    task.state = State::runnable;
    epoll_restore_mask(task);
    epoll_discard_wait(task);
    return true;
}

void epoll_stop_wait(Task& task) {
    if (task.wait != Wait::epoll_wait || epoll_resume_wait(task))
        return;
    task.frame.rax = uint64_t(-4);
    task.frame.rip += 2;
    task.deadline = 0;
    task.wait = Wait::none;
    epoll_restore_mask(task);
    epoll_discard_wait(task);
}

const void* readiness_source(const Handle& handle) {
    if (handle.pipe)
        return handle.pipe;
    if (handle.socket)
        return handle.socket;
    if (handle.inet)
        return handle.inet;
    if (handle.inet6)
        return handle.inet6;
    return &handle;
}

static uint32_t epoll_leaf_notification(EpollItem& item, const void* source, uint32_t events) {
    auto target = item.handle;
    uint32_t ready = readiness(target, nullptr) & (item.event.events | 8 | 16);
    uint32_t pending = 0;
    if (auto timer = target->timer) {
        auto notification = timerfd_notification(*timer);
        if (notification != item.observed_notification) {
            item.observed_notification = notification;
            pending = ready & 1;
        }
    } else
        pending = ready & ~item.last_ready;
    if (source && readiness_source(*target) == source)
        pending |= ready & events;
    item.last_ready = ready;
    return pending;
}

static void epoll_notify_exclusive(const void* source, uint32_t events,
                                   uint64_t signal_wait_queue) {
    if (!exclusive_first)
        return;
    unsigned waiting[max_epolls]{};
    for (auto& task : tasks)
        if (task.state == State::blocked && task.wait == Wait::epoll_wait)
            ++waiting[task.epoll_wait_handle->epoll->index];

    // Each claim spends one direct waiter. Read and write wakeups can occur on
    // the same pipe, and signalfd descriptions can share a signal wait queue.
    struct Claim {
        const void* source;
        uint32_t events;
    } claims[max_tasks];

    unsigned count = 0;
    for (auto item = exclusive_first; item;) {
        auto& watch = *item;
        item = watch.exclusive_next;
        if (!watch.live()) {
            epoll_unlink_exclusive(watch);
            continue;
        }
        if (watch.signal_wait_queue != signal_wait_queue)
            continue;
        uint32_t pending = signal_wait_queue ? watch.event.events & 1
                                             : epoll_leaf_notification(watch, source, events);
        if (!pending)
            continue;
        // All signalfd watches in this pass use the same signal wait queue.
        const void* key = signal_wait_queue ? nullptr : readiness_source(*watch.handle);
        unsigned claim = 0;
        while (claim < count && claims[claim].source != key)
            ++claim;
        if (claim < count)
            pending &= ~claims[claim].events;
        if (!pending)
            continue;

        auto& epoll = *watch.exclusive_owner;
        watch.pending |= pending;
        ++epoll.notification;
        if (waiting[epoll.index]) {
            --waiting[epoll.index];
            if (claim == count)
                claims[count++] = {key, pending};
            else
                claims[claim].events |= pending;
        }
    }
}

static void epoll_refresh(Epoll& epoll, const void* source, uint32_t events, uint64_t& visited) {
    uint64_t bit = 1ull << epoll.index;
    if (visited & bit)
        return;
    visited |= bit;
    bool notified = false;
    for (auto& item : epoll.items) {
        if (!item.enabled || item.exclusive_owner || item.signal_wait_queue || !item.live())
            continue;
        uint32_t pending = 0;
        auto target = item.handle;
        if (auto child = target->epoll) {
            epoll_refresh(*child, source, events, visited);
            if (item.observed_notification != child->notification) {
                item.observed_notification = child->notification;
                // Nested wakeups are keyed to POLLIN, even when a poll
                // samples both POLLIN and POLLRDNORM.
                pending = item.event.events & 1;
            }
        } else
            pending = epoll_leaf_notification(item, source, events);
        item.pending |= pending;
        notified |= pending != 0;
    }
    if (notified)
        ++epoll.notification;
}

static void epoll_notify_source(const void* source, uint32_t events) {
    if (source)
        descriptor_wait_notify(source, events);
    epoll_notify_exclusive(source, events);
    uint64_t visited = 0;
    for (auto poll : epolls)
        if (poll)
            epoll_refresh(*poll, source, events, visited);
}

void epoll_notify(Handle* source, uint32_t events) {
    epoll_notify_source(source ? readiness_source(*source) : nullptr, events);
}

void epoll_signal_notify(const SignalHandlers& handlers) {
    if (!handlers.descriptor_wait_queue)
        return;
    epoll_notify_exclusive(nullptr, 0, handlers.descriptor_wait_queue);
    for (auto poll : epolls) {
        if (!poll)
            continue;
        bool notified = false;
        for (auto& item : poll->items)
            if (item.enabled && !item.exclusive_owner &&
                item.signal_wait_queue == handlers.descriptor_wait_queue && item.live()) {
                uint32_t pending = item.event.events & 1;
                item.pending |= pending;
                notified |= pending != 0;
            }
        if (notified)
            ++poll->notification;
    }
}

static constexpr unsigned epoll_max_links = 4;

// The installed graph is acyclic. Compute the longest path from a vertex and
// reject any descendant that would close a cycle through the proposed parent.
static unsigned epoll_depth(const uint64_t* graph, unsigned node, unsigned forbidden,
                            uint8_t (&depth)[64]) {
    if (node == forbidden)
        return epoll_max_links + 1;
    if (depth[node] != UINT8_MAX)
        return depth[node];
    unsigned longest = 0;
    for (auto children = graph[node]; children; children &= children - 1) {
        unsigned next = __builtin_ctzll(children);
        unsigned child = epoll_depth(graph, next, forbidden, depth);
        if (child >= epoll_max_links) {
            longest = epoll_max_links + 1;
            break;
        }
        if (child + 1 > longest)
            longest = child + 1;
    }
    depth[node] = longest;
    return longest;
}

static bool epoll_can_nest(const Epoll& parent, const Epoll& child) {
    uint64_t children[64]{}, parents[64]{};
    for (auto poll : epolls)
        if (poll)
            for (auto& item : poll->items)
                if (item.live() && item.handle->epoll) {
                    unsigned index = item.handle->epoll->index;
                    children[poll->index] |= 1ull << index;
                    parents[index] |= 1ull << poll->index;
                }
    uint8_t down[64], up[64];
    memset(down, UINT8_MAX, sizeof(down));
    memset(up, UINT8_MAX, sizeof(up));
    unsigned descendants = epoll_depth(children, child.index, parent.index, down);
    unsigned ancestors = epoll_depth(parents, parent.index, child.index, up);
    return ancestors + 1 + descendants <= epoll_max_links;
}

void epoll_close(Epoll* poll) {
    for (auto& item : poll->items)
        epoll_unlink_exclusive(item);
    for (auto& entry : epolls)
        if (entry == poll)
            entry = nullptr;
    release(poll);
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
    if (s && f->rax == 49)
        return socket_unix_bind(*current, *s, b, c);
    if (s && s->type == 2 && f->rax == 42)
        return socket_datagram_connect(*current, *s, b, uint32_t(c));
    if (s && s->type == 2 && f->rax == 50)
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
        if (!unix_socket_type(b & 0xf) || (b & ~uint64_t(0x8080f)) || c)
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
            if (other.used && other.type == s->type && other.listener &&
                (!addr.abstract() ? file_node(other.bound_node) == target
                                  : other.local_name->address().same(addr)))
                listener = &other;
        if (!listener || listener->read_closed)
            return -111;
        if (listener->queue_size >= listener->backlog)
            return -11;
        auto server = allocate_socket(s->type);
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
        epoll_notify_source(listener, read_events);
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
        epoll_notify_source(s, readiness(h, current));
        if (s->type != 2)
            if (auto peer = s->peer; peer && peer->description)
                epoll_notify_source(peer, readiness(peer->description, current));
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
        if (a != 1 || !unix_socket_type(b & 0xf) || c || (b & ~uint64_t(0x8080f)))
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
        if (s->uses_record_queue() && (c == 7 || c == 8)) {
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
        if (s->uses_record_queue() && (c == 7 || c == 8))
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
        uint32_t flags = f->rax == 291 ? uint32_t(a) : 0;
        if ((f->rax == 213 && int32_t(a) <= 0) || (flags & ~02000000u))
            return -22;
        int number = reserve_fd(*current, 0, flags & 02000000);
        if (number < 0)
            return number;
        auto poll = static_cast<Epoll*>(alloc(sizeof(Epoll)));
        if (!poll) {
            discard_reserved_fd(*current->files, number);
            return -12;
        }
        *poll = {};
        bool registered = false;
        for (auto& entry : epolls)
            if (!entry) {
                poll->index = unsigned(&entry - epolls);
                entry = poll;
                registered = true;
                break;
            }
        if (!registered) {
            release(poll);
            discard_reserved_fd(*current->files, number);
            return -23;
        }
        auto fd = open_handle(nullptr, 2);
        if (!fd) {
            epoll_close(poll);
            discard_reserved_fd(*current->files, number);
            return -23;
        }
        fd->epoll = poll;
        install_reserved_fd(*current->files, number, fd);
        return number;
    }
    case 233: {
        uint32_t operation = uint32_t(b);
        EpollEvent event{};
        if ((operation == 1 || operation == 3) &&
            !current->memory->space.copy_in(&event, d, sizeof(event)))
            return -14;
        auto target = handle(c);
        if (!h || !target)
            return -9;
        if (!handle_has_poll(*target))
            return -1;
        if (!h->epoll || target == h)
            return -22;
        if ((event.events & epoll_exclusive) &&
            (operation != 1 || target->epoll || (event.events & ~epoll_exclusive_events)))
            return -22;
        EpollItem* item = nullptr;
        for (auto& existing : h->epoll->items)
            if (existing.used && existing.fd == int(c) && existing.handle == target &&
                existing.generation == target->generation)
                item = &existing;
        if (operation == 2) {
            if (!item)
                return -2;
            epoll_unlink_exclusive(*item);
            item->used = false;
            return 0;
        }
        if (operation == 1 && item)
            return -17;
        if (operation == 3 && !item)
            return -2;
        if (operation == 3 && item->exclusive_owner)
            return -22;
        if (operation != 1 && operation != 3)
            return -22;
        if (operation == 1 && target->epoll && !epoll_can_nest(*h->epoll, *target->epoll))
            return -40;
        if (!item)
            for (auto& candidate : h->epoll->items)
                if (!candidate.live()) {
                    item = &candidate;
                    break;
                }
        if (!item)
            return -28;
        uint64_t wait_queue = 0;
        if (target->signal_descriptor) {
            auto& handler_queue = current->handlers->descriptor_wait_queue;
            if (operation == 1 && !handler_queue)
                handler_queue = next_signal_wait_queue++;
            wait_queue = operation == 1 ? handler_queue : item->signal_wait_queue;
        }
        uint32_t ready = readiness(target, current) & (event.events | 8 | 16);
        uint64_t notification = target->epoll   ? target->epoll->notification
                                : target->timer ? timerfd_notification(*target->timer)
                                                : 0;
        epoll_unlink_exclusive(*item);
        *item = {target, target->generation, int(c),    event, true, true, ready,
                 ready,  notification,       wait_queue};
        if (event.events & epoll_exclusive)
            epoll_append_exclusive(*h->epoll, *item);
        if (ready)
            ++h->epoll->notification;
        epoll_notify();
        return 0;
    }
    case 232:
    case 281:
    case 441:
        return epoll_wait(*current, h, *f);
    default:
        return -38;
    }
}
} // namespace ax
