// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/ipc/system_v_message_queues.cpp
 * @brief   System V message queues.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Manages queue IDs, message selection, permissions, and blocked senders and
 * receivers.
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
#include "ipc/system_v_message_queues.hpp"
#include "ipc/system_v_permissions.hpp"
#include "core/time.hpp"

namespace ax {
namespace {
constexpr unsigned max_queues = 32000, slot_mask = 32767;
constexpr size_t max_message = 8192, default_capacity = 16384;
constexpr unsigned ipc_create = 01000, ipc_exclusive = 02000, no_wait = 04000;
constexpr unsigned truncate_message = 010000, except_type = 020000, copy_message = 040000;

struct Status {
    SystemVPermission permission;
    uint64_t sent, received, changed, bytes, count, capacity;
    int32_t sender_pid, receiver_pid;
    uint64_t reserved[2];
};

static_assert(sizeof(Status) == 120 && offsetof(Status, capacity) == 88);

struct Message {
    Message* next;
    size_t size;
    int64_t type;

    void* data() {
        return this + 1;
    }
};

struct Queue {
    Status status;
    Message* first;
    Message** tail;
    MessageQueueRequest* senders;
    MessageQueueRequest* receivers;

    bool fits(size_t size) const {
        return status.count < status.capacity && status.bytes <= status.capacity &&
               size <= status.capacity - status.bytes;
    }
};
} // namespace

struct MessageQueueRequest {
    Queue* queue;
    Task* task;
    MessageQueueRequest* next;
    Message* message;
    bool sending;
};

namespace {
static Queue* queues[max_queues];
static uint16_t generations[max_queues];
static unsigned live_queues;
static uint64_t total_bytes, total_messages;

int id_for(unsigned slot) {
    return (unsigned(generations[slot]) << 15) | slot;
}

Queue* find(int id) {
    unsigned slot = unsigned(id) & slot_mask;
    return id >= 0 && slot < max_queues && id == id_for(slot) ? queues[slot] : nullptr;
}

int open_queue(int key, unsigned flags) {
    unsigned empty = max_queues;
    for (unsigned slot = 0; slot < max_queues; ++slot) {
        auto* queue = queues[slot];
        if (!queue) {
            if (empty == max_queues)
                empty = slot;
            if (!key)
                break;
            continue;
        }
        const auto& permission = queue->status.permission;
        if (!key || permission.key != key)
            continue;
        if ((flags & (ipc_create | ipc_exclusive)) == (ipc_create | ipc_exclusive))
            return -17;
        return permission.allows(current_task()->credentials, flags | flags >> 3 | flags >> 6)
                   ? id_for(slot)
                   : -13;
    }
    if (key && !(flags & ipc_create))
        return -2;
    if (empty == max_queues)
        return -28;
    auto* queue = static_cast<Queue*>(alloc(sizeof(Queue)));
    if (!queue)
        return -12;
    *queue = {};
    const auto& credentials = current_task()->credentials;
    auto& status = queue->status;
    status.permission.key = key;
    status.permission.uid = status.permission.creator_uid = credentials.user.effective;
    status.permission.gid = status.permission.creator_gid = credentials.group.effective;
    status.permission.mode = flags & 0777;
    status.permission.sequence = generations[empty];
    status.changed = clock_realtime_ticks() / 100;
    status.capacity = default_capacity;
    queue->tail = &queue->first;
    queues[empty] = queue;
    ++live_queues;
    return id_for(empty);
}

void detach(MessageQueueRequest& request) {
    auto& queue = *request.queue;
    auto** link = request.sending ? &queue.senders : &queue.receivers;
    while (*link != &request)
        link = &(*link)->next;
    *link = request.next;
    request.queue = nullptr;
}

void wake(Task& task) {
    task.wait = Wait::none;
    if (task.state != State::stopped)
        task.state = State::runnable;
}

void finish(Task& task, int64_t result) {
    message_queue_discard(task);
    task.frame.rip += 2;
    task.frame.rax = result;
    wake(task);
}

int64_t wait_for(Queue& queue, Message* message) {
    auto* request = static_cast<MessageQueueRequest*>(alloc(sizeof(MessageQueueRequest)));
    if (!request) {
        release(message);
        return -12;
    }
    *request = {&queue, current_task(), nullptr, message, message != nullptr};
    auto** link = request->sending ? &queue.senders : &queue.receivers;
    while (*link)
        link = &(*link)->next;
    *link = request;
    current_task()->message_queue_request = request;
    current_task()->wait = Wait::message_queue;
    current_task()->state = State::blocked;
    return would_block;
}

int64_t maximum_type(int64_t selector) {
    return selector == INT64_MIN ? INT64_MAX : -selector;
}

bool matches(int64_t type, int64_t selector, unsigned flags) {
    if (selector < 0)
        return type <= maximum_type(selector);
    if (!selector)
        return true;
    return flags & except_type ? type != selector : type == selector;
}

void record_receive(Queue& queue, int pid) {
    queue.status.receiver_pid = pid;
    queue.status.received = clock_realtime_ticks() / 100;
}

void publish(Queue& queue, Message* message, const Task& sender) {
    queue.status.sender_pid = sender.process->pid;
    queue.status.sent = clock_realtime_ticks() / 100;
    for (auto* request = queue.receivers; request;) {
        auto* next = request->next;
        auto& receiver = *request->task;
        const auto& call = receiver.frame;
        if (matches(message->type, int64_t(call.r10), call.r8)) {
            if (call.rdx < message->size && !(call.r8 & truncate_message))
                finish(receiver, -7);
            else {
                record_receive(queue, receiver.pid);
                detach(*request);
                request->message = message;
                wake(receiver);
                return;
            }
        }
        request = next;
    }
    *queue.tail = message;
    queue.tail = &message->next;
    queue.status.bytes += message->size;
    ++queue.status.count;
    total_bytes += message->size;
    ++total_messages;
}

void wake_senders(Queue& queue) {
    for (auto* request = queue.senders; request;) {
        auto* next = request->next;
        auto* message = request->message;
        auto& sender = *request->task;
        if (queue.fits(message->size)) {
            if (!queue.status.permission.allows(sender.credentials, 2))
                finish(sender, -13);
            else {
                request->message = nullptr;
                finish(sender, 0);
                publish(queue, message, sender);
            }
        }
        request = next;
    }
}

int64_t send(int id, uint64_t pointer, size_t size, unsigned flags) {
    auto& memory = current_task()->memory->space;
    int64_t type;
    if (!memory.copy_in(&type, pointer, sizeof(type)))
        return -14;
    if (size > max_message || type < 1 || id < 0)
        return -22;
    auto* message = static_cast<Message*>(alloc(sizeof(Message) + size));
    if (!message)
        return -12;
    *message = {nullptr, size, type};
    auto* queue = find(id);
    int result = 0;
    if (size && !memory.copy_in(message->data(), pointer + sizeof(type), size))
        result = -14;
    else if (!queue)
        result = -22;
    else if (!queue->status.permission.allows(current_task()->credentials, 2))
        result = -13;
    if (result) {
        release(message);
        return result;
    }
    if (queue->fits(size)) {
        publish(*queue, message, *current_task());
        return 0;
    }
    if (!(flags & no_wait))
        return wait_for(*queue, message);
    release(message);
    return -11;
}

Message** select(Queue& queue, int64_t selector, unsigned flags) {
    if (flags & copy_message) {
        auto** link = &queue.first;
        for (; *link && selector > 0; --selector)
            link = &(*link)->next;
        return selector == 0 && *link ? link : nullptr;
    }
    Message** found = nullptr;
    for (auto** link = &queue.first; *link; link = &(*link)->next) {
        const auto type = (*link)->type;
        if (!matches(type, selector, flags))
            continue;
        if (selector >= 0 || type == 1)
            return link;
        found = link;
        selector = -(type - 1);
    }
    return found;
}

int64_t receive_output(Task& task, Message& message, uint64_t pointer, size_t capacity) {
    auto& memory = task.memory->space;
    size_t bytes = min(capacity, message.size);
    if (!memory.copy_out(pointer, &message.type, sizeof(message.type)) ||
        (bytes && !memory.copy_out(pointer + sizeof(message.type), message.data(), bytes)))
        return -14;
    return bytes;
}

int64_t receive(int id, uint64_t pointer, size_t size, int64_t selector, unsigned flags) {
    if (id < 0 || size > INT64_MAX)
        return -22;
    const bool copy = flags & copy_message;
    if (copy) {
        if ((flags & except_type) || !(flags & no_wait))
            return -22;
        if (size && !current_task()->memory->space.valid(pointer, min(size, max_message)))
            return -14;
    }
    auto* queue = find(id);
    if (!queue)
        return -22;
    if (!queue->status.permission.allows(current_task()->credentials, 4))
        return -13;
    auto** link = select(*queue, selector, flags);
    if (!link)
        return flags & no_wait ? -42 : wait_for(*queue, nullptr);
    auto* message = *link;
    if (size < message->size) {
        if (!(flags & truncate_message))
            return -7;
        if (copy)
            return -22;
    }
    if (copy)
        return receive_output(*current_task(), *message, pointer, size);
    // A destructive receive consumes the message even when copying to userspace fails.
    *link = message->next;
    if (!*link)
        queue->tail = link;
    queue->status.bytes -= message->size;
    --queue->status.count;
    total_bytes -= message->size;
    --total_messages;
    record_receive(*queue, current_task()->process->pid);
    wake_senders(*queue);
    const auto result = receive_output(*current_task(), *message, pointer, size);
    release(message);
    return result;
}

void remove_queue(Queue& queue, unsigned slot) {
    while (queue.senders)
        finish(*queue.senders->task, -43);
    while (queue.receivers)
        finish(*queue.receivers->task, -43);
    while (auto* message = queue.first) {
        queue.first = message->next;
        release(message);
    }
    total_bytes -= queue.status.bytes;
    total_messages -= queue.status.count;
    --live_queues;
    queues[slot] = nullptr;
    ++generations[slot];
    release(&queue);
}

int info(uint64_t pointer, bool usage) {
    const int32_t output[] = {
        usage ? int32_t(live_queues) : 512000,
        usage ? int32_t(min(total_messages, uint64_t(INT32_MAX))) : int32_t(default_capacity),
        max_message,
        default_capacity,
        max_queues,
        16,
        usage ? int32_t(min(total_bytes, uint64_t(INT32_MAX))) : int32_t(default_capacity),
        65535};
    if (!current_task()->memory->space.copy_out(pointer, output, sizeof(output)))
        return -14;
    for (unsigned slot = max_queues; slot > 0; --slot)
        if (queues[slot - 1])
            return slot - 1;
    return 0;
}

int control(int id, int command, uint64_t pointer) {
    if (id < 0)
        return -22;
    if (command == 3 || command == 12)
        return info(pointer, command == 12);
    const bool by_slot = command == 11 || command == 13;
    auto& memory = current_task()->memory->space;
    Status input;
    if (command == 1 && !memory.copy_in(&input, pointer, sizeof(input)))
        return -14;
    auto* queue = by_slot ? (unsigned(id) < max_queues ? queues[id] : nullptr) : find(id);
    if (!queue)
        return -22;
    auto& status = queue->status;
    const auto& credentials = current_task()->credentials;
    if (command == 0 || command == 1) {
        if (!status.permission.controls(credentials))
            return -1;
        if (command == 0) {
            remove_queue(*queue, unsigned(id) & slot_mask);
            return 0;
        }
        if (input.capacity > default_capacity && !capable(credentials, Capability::sys_resource))
            return -1;
        if (input.permission.uid == UINT32_MAX || input.permission.gid == UINT32_MAX)
            return -22;
        status.permission.uid = input.permission.uid;
        status.permission.gid = input.permission.gid;
        status.permission.mode = input.permission.mode & 0777;
        status.capacity = input.capacity;
        status.changed = clock_realtime_ticks() / 100;
        for (auto* request = queue->receivers; request;) {
            auto* next = request->next;
            if (!status.permission.allows(request->task->credentials, 4))
                finish(*request->task, -13);
            request = next;
        }
        wake_senders(*queue);
        return 0;
    }
    if (command != 2 && !by_slot)
        return -22;
    if (command != 13 && !status.permission.allows(credentials, 4))
        return -13;
    return memory.copy_out(pointer, &status, sizeof(status)) ? (by_slot ? id_for(id) : 0) : -14;
}
} // namespace

void message_queue_discard(Task& task) {
    auto* request = task.message_queue_request;
    if (!request)
        return;
    if (request->queue)
        detach(*request);
    release(request->message);
    release(request);
    task.message_queue_request = nullptr;
}

void message_queue_resume(Task& task) {
    auto* request = task.message_queue_request;
    if (!request || request->queue)
        return;
    // Complete a handed-off receive before signal delivery. Stack growth applies
    // to the receiving task's address space and limits, even across a context switch.
    auto* previous = current_task();
    set_current_task(&task);
    auto result = receive_output(task, *request->message, task.frame.rsi, task.frame.rdx);
    set_current_task(previous);
    finish(task, result);
}

int64_t message_queue_syscall(Frame* f) {
    switch (f->rax) {
    case 68:
        return open_queue(int32_t(f->rdi), f->rsi);
    case 69:
        return send(int32_t(f->rdi), f->rsi, f->rdx, f->r10);
    case 70:
        return receive(int32_t(f->rdi), f->rsi, f->rdx, int64_t(f->r10), f->r8);
    case 71:
        return control(int32_t(f->rdi), int32_t(f->rsi), f->rdx);
    default:
        return -38;
    }
}
} // namespace ax
