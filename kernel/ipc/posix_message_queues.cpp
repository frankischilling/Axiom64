// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/ipc/posix_message_queues.cpp
 * @brief   POSIX message queues.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Implements named queues, priority delivery, blocking operations, and
 * notification state.
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
#include "ipc/posix_message_queues.hpp"
#include "core/time.hpp"
#include "fs/descriptor.hpp"
#include "fs/xattr.hpp"
#include "ipc/ipc.hpp"
#include "net/netlink.hpp"
#include "process/signals.hpp"

namespace ax {
namespace {
constexpr unsigned create = 0100, exclusive = 0200, nonblocking = 04000;
constexpr unsigned priority_count = 32768, default_queues = 256;
constexpr int64_t default_messages = 10, default_message_size = 8192;

struct Attributes {
    int64_t flags, maximum, message_size, count;
    int64_t reserved[4];
};

static_assert(sizeof(Attributes) == 64);

struct Message {
    Message* next;
    size_t size;
    uint32_t priority;
};

struct Notification {
    int owner, kind, signal;
    uint64_t value, exec_generation;
    Handle* delivery_handle;
    NetlinkFrame* delivery;
};

struct Queue {
    Queue* next;
    Attributes attributes;
    Message* messages;
    PosixQueueRequest* senders;
    PosixQueueRequest* receivers;
    Notification notification;
    uint64_t charge, queued_bytes;
    uint32_t uid;
};

static Node* queue_root;
static Queue* queues;
static unsigned live_queues;

Queue* queue_of(const Node* node) {
    return node && node->mount->ops == &posix_queue_filesystem()
               ? static_cast<Queue*>(node->filesystem_data)
               : nullptr;
}

Queue* queue_for(int fd, Handle*& handle) {
    handle =
        fd >= 0 && unsigned(fd) < max_fds ? current_task()->files->entries[fd].handle : nullptr;
    return handle && !(handle->flags & 010000000) ? queue_of(handle->node) : nullptr;
}

int queue_path(uint64_t address, Path& path) {
    if (!queue_root)
        return -19;
    path.base = queue_root;
    path.error = 0;
    auto& memory = current_task()->memory->space;
    for (size_t i = 0; i < 256; ++i) {
        char ch;
        if (!memory.copy_in(&ch, address + i, 1))
            return -14;
        if (ch == '/')
            return -13;
        path.text[i] = ch;
        if (!ch) {
            if (!i || !strcmp(path.text, ".") || !strcmp(path.text, ".."))
                return -2;
            return 0;
        }
    }
    return -36;
}

int create_queue(Node* parent, const char* name, unsigned mode, const Attributes& attr,
                 Node*& node) {
    const auto& creds = current_task()->credentials;
    bool privileged = capable(creds, Capability::sys_resource);
    if (attr.maximum <= 0 || attr.message_size <= 0 ||
        attr.maximum > (privileged ? 65536 : default_messages) ||
        attr.message_size > (privileged ? 16777216 : default_message_size))
        return -22;
    if (node_readonly(parent))
        return -30;
    if (!privileged && live_queues >= default_queues)
        return -28;
    uint64_t charge = attr.maximum * (uint64_t(attr.message_size) + 48) +
                      min(uint64_t(attr.maximum), uint64_t(priority_count)) * 48;
    uint64_t used = 0;
    auto uid = creds.user.real;
    for (auto* queue = queues; queue; queue = queue->next)
        if (queue->uid == uid)
            used += queue->charge;
    auto limit = current_task()->process->limits.soft(Resource::message_queue);
    if (used > limit || charge > limit - used)
        return -24;
    auto* queue = static_cast<Queue*>(alloc(sizeof(Queue)));
    if (!queue)
        return -12;
    int result = ramfs_ops.create(parent, name, regular_file | (mode & 0777), nullptr, node);
    if (result) {
        release(queue);
        return result;
    }
    *queue = {};
    queue->attributes.maximum = attr.maximum;
    queue->attributes.message_size = attr.message_size;
    queue->uid = uid;
    queue->charge = charge;
    queue->next = queues;
    queues = queue;
    ++live_queues;
    node->filesystem_data = queue;
    node->size = 80;
    return 0;
}

int open_queue(uint64_t name, unsigned flags, unsigned mode, uint64_t pointer) {
    Attributes attr{0, default_messages, default_message_size, 0, {}};
    if (pointer && !current_task()->memory->space.copy_in(&attr, pointer, sizeof(attr)))
        return -14;
    Path path;
    int error = queue_path(name, path);
    if (error)
        return error;
    Node* node = nullptr;
    int access = flags & 3;
    if (access == 3)
        return -22;
    error = ramfs_ops.lookup(queue_root, path.text, node);
    if (!error) {
        if ((flags & (create | exclusive)) == (create | exclusive))
            return -17;
        error = node_access(node, access == 0 ? 4 : access == 1 ? 2 : 6);
    } else if (!(flags & create))
        return error;
    bool creating = error == -2;
    if (error && !creating)
        return error;

    int fd = reserve_fd(*current_task(), 0, true);
    if (fd < 0)
        return fd;
    if (creating)
        error = create_queue(queue_root, path.text, mode & ~current_task()->fs->umask, attr, node);
    auto* handle = error ? nullptr : open_handle(node, flags & (nonblocking | 3), &error);
    if (!handle) {
        if (creating && node && queue_of(node)) {
            ramfs_ops.remove(node);
            posix_queue_reap(node);
        }
        discard_reserved_fd(*current_task()->files, fd);
        return error;
    }
    handle->opened_dentry = node;
    install_reserved_fd(*current_task()->files, fd, handle);
    return fd;
}

int unlink_queue(uint64_t name) {
    Path path;
    int error = queue_path(name, path);
    return error ? error : remove_node(path, false);
}

void notify(Queue& queue, const Task* sender) {
    auto entry = queue.notification;
    queue.notification = {};
    if (entry.delivery) {
        static_cast<uint8_t*>(static_cast<void*>(entry.delivery + 1))[31] = sender ? 1 : 2;
        netlink_publish_delivery(entry.delivery_handle->netlink, entry.delivery);
        close_handle(entry.delivery_handle);
        epoll_notify();
        return;
    }
    if (!entry.owner || !sender || entry.kind != 0 || !entry.signal)
        return;
    for (auto& task : tasks)
        if (task.state != State::empty && task.state != State::zombie &&
            task.process->pid == entry.owner) {
            if (task.process->exec_generation == entry.exec_generation)
                queue_message_signal(task.process, entry.signal, *sender, entry.value);
            break;
        }
}

void enqueue(Queue& queue, Message* message, const Task* sender) {
    auto** link = &queue.messages;
    while (*link && (*link)->priority >= message->priority)
        link = &(*link)->next;
    message->next = *link;
    *link = message;
    queue.queued_bytes += message->size;
    if (++queue.attributes.count == 1 && sender && queue.notification.owner)
        notify(queue, sender);
    epoll_notify();
}

int64_t output(Task& task, Message& message, const Frame& call) {
    auto& space = task.memory->space;
    if ((call.r10 && !space.copy_out(call.r10, &message.priority, sizeof(message.priority))) ||
        (message.size && !space.copy_out(call.rsi, &message + 1, message.size)))
        return -14;
    return message.size;
}

int64_t metadata(Node* node, uint64_t offset, void* buffer, size_t length) {
    auto* queue = queue_of(node);
    if (!queue)
        return -22;
    char text[80], *end = text;
    auto field = [&](const char* label, uint64_t value, unsigned width) {
        while (*label)
            *end++ = *label++;
        char digits[20];
        unsigned used = 0;
        do {
            digits[used++] = '0' + value % 10;
            value /= 10;
        } while (value);
        unsigned padding = width > used ? width - used : 0;
        while (used)
            *end++ = digits[--used];
        for (unsigned i = 0; i < padding; ++i)
            *end++ = ' ';
    };
    const auto entry = queue->notification;
    field("QSIZE:", queue->queued_bytes, 10);
    field(" NOTIFY:", entry.kind, 5);
    field(" SIGNO:", entry.kind == 0 ? entry.signal : 0, 5);
    field(" NOTIFY_PID:", entry.owner, 6);
    *end++ = '\n';
    auto size = size_t(end - text);
    if (offset >= size)
        return 0;
    length = min(length, size - size_t(offset));
    memcpy(buffer, text + offset, length);
    return length;
}
} // namespace

struct PosixQueueRequest {
    Handle* handle;
    Task* task;
    PosixQueueRequest* next;
    Message* message;
    uint64_t deadline;
    bool sending, listed;
};

namespace {
void detach(PosixQueueRequest& request) {
    auto& queue = *queue_of(request.handle->node);
    auto** link = request.sending ? &queue.senders : &queue.receivers;
    while (*link != &request)
        link = &(*link)->next;
    *link = request.next;
    request.listed = false;
}

void wake(Task& task) {
    task.wait = Wait::none;
    if (task.state != State::stopped)
        task.state = State::runnable;
}

void finish(Task& task, int64_t result) {
    posix_queue_discard(task);
    task.frame.rip += 2;
    task.frame.rax = result;
    wake(task);
}

int64_t block(Handle& handle, uint64_t deadline, Message* message) {
    auto* request = static_cast<PosixQueueRequest*>(alloc(sizeof(PosixQueueRequest)));
    if (!request) {
        release(message);
        return -12;
    }
    retain(&handle);
    *request = {&handle, current_task(), nullptr, message, deadline, message != nullptr, true};
    auto& queue = *queue_of(handle.node);
    auto** link = request->sending ? &queue.senders : &queue.receivers;
    while (*link)
        link = &(*link)->next;
    *link = request;
    current_task()->posix_queue_request = request;
    current_task()->wait = Wait::posix_queue;
    current_task()->state = State::blocked;
    return would_block;
}

void send_message(Queue& queue, Message* message, const Task& sender) {
    while (queue.receivers && posix_queue_expire(*queue.receivers->task)) {
    }
    if (auto* receiver = queue.receivers) {
        detach(*receiver);
        receiver->message = message;
        wake(*receiver->task);
        return;
    }
    enqueue(queue, message, &sender);
}

int parse_deadline(uint64_t address, uint64_t& deadline) {
    if (!address)
        return 0;
    int64_t input[2];
    if (!current_task()->memory->space.copy_in(input, address, sizeof(input)))
        return -14;
    if (input[0] < 0 || input[1] < 0 || input[1] >= 1000000000)
        return -22;
    uint64_t fraction = (input[1] + 9999999) / 10000000;
    deadline = uint64_t(input[0]) <= (UINT64_MAX - fraction) / 100
                   ? uint64_t(input[0]) * 100 + fraction
                   : UINT64_MAX;
    return 0;
}

int64_t send(Frame& call, uint64_t deadline) {
    if (uint32_t(call.r10) >= priority_count)
        return -22;
    Handle* handle;
    auto* queue = queue_for(int(call.rdi), handle);
    if (!queue || (handle->flags & 3) == 0)
        return -9;
    auto size = call.rdx;
    if (size > uint64_t(queue->attributes.message_size))
        return -90;
    auto* message = static_cast<Message*>(alloc(sizeof(Message) + size));
    if (!message)
        return -12;
    *message = {nullptr, size, uint32_t(call.r10)};
    if (size && !current_task()->memory->space.copy_in(message + 1, call.rsi, size)) {
        release(message);
        return -14;
    }
    if (queue->attributes.count < queue->attributes.maximum) {
        send_message(*queue, message, *current_task());
        handle->node->mtime = handle->node->ctime = node_now();
        return 0;
    }
    if (!(handle->flags & nonblocking) && (!call.r8 || deadline > clock_realtime_ticks()))
        return block(*handle, deadline, message);
    release(message);
    return handle->flags & nonblocking ? -11 : -110;
}

int64_t receive(Frame& call, uint64_t deadline) {
    Handle* handle;
    auto* queue = queue_for(int(call.rdi), handle);
    if (!queue || (handle->flags & 3) == 1)
        return -9;
    if (call.rdx < uint64_t(queue->attributes.message_size))
        return -90;
    auto* message = queue->messages;
    if (!message) {
        if (handle->flags & nonblocking)
            return -11;
        if (call.r8 && deadline <= clock_realtime_ticks())
            return -110;
        return block(*handle, deadline, nullptr);
    }
    queue->messages = message->next;
    queue->queued_bytes -= message->size;
    --queue->attributes.count;
    handle->node->atime = handle->node->ctime = node_now();
    while (queue->senders && posix_queue_expire(*queue->senders->task)) {
    }
    if (auto* sender = queue->senders) {
        auto* pending = sender->message;
        sender->message = nullptr;
        // A full queue already had a message, so a sender released by a receive
        // must not trigger an empty-to-nonempty notification.
        enqueue(*queue, pending, nullptr);
        finish(*sender->task, 0);
    } else
        epoll_notify();
    auto result = output(*current_task(), *message, call);
    release(message);
    return result;
}

int control_notify(int fd, uint64_t pointer) {
    struct Event {
        uint64_t value;
        int32_t signal, kind;
        uint8_t padding[48];
    } event{};

    if (pointer && !current_task()->memory->space.copy_in(&event, pointer, sizeof(event)))
        return -14;
    if (pointer && ((event.kind < 0 || event.kind > 2) ||
                    (!event.kind && (event.signal < 0 || event.signal > 64))))
        return -22;
    Handle* handle;
    auto* queue = queue_for(fd, handle);
    if (!queue)
        return -9;
    int owner = current_task()->process->pid;
    if (!pointer) {
        if (queue->notification.owner == owner)
            notify(*queue, nullptr);
        return 0;
    }
    if (queue->notification.owner)
        return -16;
    Notification entry{
        owner,   event.kind, event.signal, event.value, current_task()->process->exec_generation,
        nullptr, nullptr};
    if (event.kind == 2) {
        uint8_t cookie[32];
        if (!current_task()->memory->space.copy_in(cookie, event.value, sizeof(cookie)))
            return -14;
        if (event.signal < 0 || unsigned(event.signal) >= max_fds)
            return -9;
        auto* target = current_task()->files->entries[event.signal].handle;
        if (!target)
            return -9;
        if (!target->netlink)
            return -88;
        int error = netlink_reserve_delivery(target->netlink, sizeof(cookie), entry.delivery);
        if (error)
            return error;
        memcpy(entry.delivery + 1, cookie, sizeof(cookie));
        retain(target);
        entry.delivery_handle = target;
    }
    queue->notification = entry;
    return 0;
}

int control_attributes(int fd, uint64_t replacement, uint64_t previous) {
    auto& space = current_task()->memory->space;
    Attributes attr;
    if (replacement && !space.copy_in(&attr, replacement, sizeof(attr)))
        return -14;
    if (replacement && (attr.flags & ~int64_t(nonblocking)))
        return -22;
    Handle* handle;
    auto* queue = queue_for(fd, handle);
    if (!queue)
        return -9;
    auto old = queue->attributes;
    old.flags = handle->flags & nonblocking;
    if (replacement)
        handle->flags = (handle->flags & ~nonblocking) | attr.flags;
    return !previous || space.copy_out(previous, &old, sizeof(old)) ? 0 : -14;
}
} // namespace

const FilesystemOps& posix_queue_filesystem() {
    static const auto ops = [] {
        auto table = ramfs_ops;
        table.create = [](Node* parent, const char* name, uint32_t mode, const char*, Node*& node) {
            if ((mode & 0170000) != regular_file)
                return -1;
            const Attributes defaults{0, default_messages, default_message_size, 0, {}};
            return create_queue(parent, name, mode, defaults, node);
        };
        table.link = [](Node*, Node*, const char*) { return -1; };
        table.rename = [](Node*, Node*, const char*, Node*) { return -1; };
        table.read = metadata;
        table.write = [](Node*, uint64_t, const void*, size_t) -> int64_t { return -22; };
        table.truncate = [](Node*, size_t) { return -22; };
        table.map_shared = [](Node*, uint64_t, size_t, uint64_t&) { return -19; };
        table.stats = [](Mount* mount, FilesystemStats& info) {
            int result = ramfs_ops.stats(mount, info);
            info.type = 0x19800202;
            return result;
        };
        return table;
    }();
    return ops;
}

void posix_queue_mount(Node* root) {
    queue_root = root;
}

bool posix_queue_mounted() {
    return queue_root != nullptr;
}

bool posix_queue_ready(const Node* node, bool write) {
    auto* queue = queue_of(node);
    return queue && (write ? queue->attributes.count < queue->attributes.maximum
                           : queue->attributes.count != 0);
}

void posix_queue_reap(Node* node) {
    if (!node || !node->removed)
        return;
    auto* queue = queue_of(node);
    if (!queue || node_referenced(node))
        return;
    auto** entry = &queues;
    while (*entry != queue)
        entry = &(*entry)->next;
    *entry = queue->next;
    auto** link = &node->parent->first_child;
    while (*link != node)
        link = &(*link)->next_sibling;
    *link = node->next_sibling;
    while (auto* message = queue->messages) {
        queue->messages = message->next;
        release(message);
    }
    --live_queues;
    notify(*queue, nullptr);
    release(queue);
    xattr_store_destroy(node->xattrs);
    *node = {};
}

void posix_queue_descriptor_closed(Handle* handle) {
    auto* queue = queue_of(handle->node);
    if (queue && !(handle->flags & 010000000) && current_task() &&
        queue->notification.owner == current_task()->process->pid)
        notify(*queue, nullptr);
}

void posix_queue_process_exit(const Process& process) {
    for (;;) {
        auto* queue = queues;
        while (queue && queue->notification.owner != process.pid)
            queue = queue->next;
        if (!queue)
            return;
        notify(*queue, nullptr);
    }
}

void posix_queue_discard(Task& task) {
    auto* request = task.posix_queue_request;
    if (!request)
        return;
    task.posix_queue_request = nullptr;
    if (request->listed)
        detach(*request);
    release(request->message);
    close_handle(request->handle);
    release(request);
}

void posix_queue_resume(Task& task) {
    auto* request = task.posix_queue_request;
    if (!request || request->listed)
        return;
    auto* previous = current_task();
    set_current_task(&task);
    auto result = output(task, *request->message, task.frame);
    set_current_task(previous);
    finish(task, result);
}

bool posix_queue_expire(Task& task) {
    auto* request = task.posix_queue_request;
    if (!request || !request->listed || !request->deadline ||
        clock_realtime_ticks() < request->deadline)
        return false;
    finish(task, -110);
    return true;
}

int64_t posix_queue_syscall(Frame* f) {
    switch (f->rax) {
    case 240:
        return open_queue(f->rdi, f->rsi, f->rdx, f->r10);
    case 241:
        return unlink_queue(f->rdi);
    case 242:
    case 243: {
        uint64_t deadline = 0;
        int error = parse_deadline(f->r8, deadline);
        if (error)
            return error;
        return f->rax == 242 ? send(*f, deadline) : receive(*f, deadline);
    }
    case 244:
        return control_notify(int(f->rdi), f->rsi);
    case 245:
        return control_attributes(int(f->rdi), f->rsi, f->rdx);
    default:
        return -38;
    }
}
} // namespace ax
