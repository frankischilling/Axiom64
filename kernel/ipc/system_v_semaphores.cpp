// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/ipc/system_v_semaphores.cpp
 * @brief   System V semaphore sets.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Manages semaphore operations, waiters, and undo state tied to process
 * lifetime.
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
#include "ipc/system_v_semaphores.hpp"
#include "ipc/system_v_permissions.hpp"
#include "core/time.hpp"

namespace ax {
namespace {
constexpr unsigned max_sets = 32000, max_members = 32000, max_operations = 500;
constexpr int max_value = 32767;
constexpr unsigned ipc_create = 01000, ipc_exclusive = 02000;
constexpr unsigned no_wait = 04000, undo_flag = 010000;

struct Operation {
    uint16_t member;
    int16_t change, flags;
};

static_assert(sizeof(Operation) == 6);

struct Status {
    SystemVPermission permission;
    uint64_t operated, operated_high, changed, changed_high, members, reserved[2];
};

static_assert(sizeof(Status) == 104);

struct Member {
    int value, pid;
};
struct Set;
struct Adjustment;
} // namespace

struct SemaphoreUndo {
    unsigned owners;
    Adjustment* entries;
};

struct SemaphoreRequest {
    Set* set;
    Task* task;
    SemaphoreRequest* next;
    Adjustment* undo;
    uint64_t deadline;
    unsigned count, blocked;

    Operation* operations() {
        return reinterpret_cast<Operation*>(this + 1);
    }
};

namespace {
struct Set {
    Status status;
    SemaphoreRequest* waiting;
    Adjustment* adjustments;

    Member* members() {
        return reinterpret_cast<Member*>(this + 1);
    }
};

struct Adjustment {
    SemaphoreUndo* owner;
    Set* set;
    Adjustment* owner_next;
    Adjustment* set_next;

    int16_t* values() {
        return reinterpret_cast<int16_t*>(this + 1);
    }
};

static Set* sets[max_sets];
static uint16_t generations[max_sets];
static unsigned live_sets, live_members;

int id_for(unsigned slot) {
    return (unsigned(generations[slot]) << 15) | slot;
}

Set* find(int id) {
    unsigned slot = unsigned(id) & 32767;
    if (id < 0 || slot >= max_sets || id != id_for(slot))
        return nullptr;
    return sets[slot];
}

SemaphoreUndo* undo_group(Task& task) {
    if (!task.semaphore_undo) {
        auto* undo = static_cast<SemaphoreUndo*>(alloc(sizeof(SemaphoreUndo)));
        if (!undo)
            return nullptr;
        *undo = {1, nullptr};
        task.semaphore_undo = undo;
    }
    return task.semaphore_undo;
}

Adjustment* undo_for(Task& task, Set& set) {
    auto* group = undo_group(task);
    if (!group)
        return nullptr;
    for (auto* item = group->entries; item; item = item->owner_next)
        if (item->set == &set)
            return item;
    const size_t bytes = sizeof(int16_t) * set.status.members;
    auto* item = static_cast<Adjustment*>(alloc(sizeof(Adjustment) + bytes));
    if (!item)
        return nullptr;
    *item = {group, &set, group->entries, set.adjustments};
    memset(item->values(), 0, bytes);
    group->entries = set.adjustments = item;
    return item;
}

void erase_adjustment(Adjustment* item) {
    auto** owner = &item->owner->entries;
    while (*owner != item)
        owner = &(*owner)->owner_next;
    *owner = item->owner_next;
    auto** set = &item->set->adjustments;
    while (*set != item)
        set = &(*set)->set_next;
    *set = item->set_next;
    release(item);
}

void clear_adjustments(Set& set, unsigned first, unsigned count) {
    for (auto* item = set.adjustments; item; item = item->set_next)
        memset(item->values() + first, 0, count * sizeof(int16_t));
}

int evaluate(SemaphoreRequest& request) {
    auto& set = *request.set;
    const auto* ops = request.operations();
    auto* undo = request.undo ? request.undo->values() : nullptr;
    unsigned i = 0;
    int result = 0;
    // Syscall and scheduler paths serialize these updates. Keep a vector with
    // repeated members in order and roll back the entire applied prefix on error.
    for (; i < request.count; ++i) {
        const auto& op = ops[i];
        auto& member = set.members()[op.member];
        const int value = member.value + op.change;
        if ((!op.change && member.value) || value < 0) {
            request.blocked = i;
            result = op.flags & no_wait ? -11 : 1;
            break;
        }
        const bool save = op.flags & undo_flag;
        const int adjustment = save ? undo[op.member] - op.change : 0;
        if (value > max_value || adjustment < -32768 || adjustment > max_value) {
            result = -34;
            break;
        }
        member.value = value;
        if (save)
            undo[op.member] = adjustment;
    }
    if (result) {
        while (i) {
            const auto& op = ops[--i];
            set.members()[op.member].value -= op.change;
            if (op.flags & undo_flag)
                undo[op.member] += op.change;
        }
        return result;
    }
    for (unsigned j = 0; j < request.count; ++j)
        set.members()[ops[j].member].pid = request.task->process->pid;
    set.status.operated = clock_realtime_ticks() / 100;
    return 0;
}

void complete(Task& task, int result) {
    semaphore_discard(task);
    task.frame.rip += 2;
    task.frame.rax = uint64_t(int64_t(result));
    task.wait = Wait::none;
    if (task.state != State::stopped)
        task.state = State::runnable;
}

void service(Set& set) {
    bool changed;
    do {
        changed = false;
        for (auto* request = set.waiting; request;) {
            auto* next = request->next;
            if (!semaphore_timeout(*request->task)) {
                int result = evaluate(*request);
                if (result != 1) {
                    complete(*request->task, result);
                    changed |= result == 0;
                }
            }
            request = next;
        }
    } while (changed && set.waiting);
}

int create(int key, int count, unsigned flags) {
    if (count < 0 || unsigned(count) > max_members)
        return -22;
    unsigned empty = max_sets;
    for (unsigned slot = 0; slot < max_sets; ++slot) {
        auto* set = sets[slot];
        if (!set) {
            if (empty == max_sets)
                empty = slot;
            continue;
        }
        if (!key || set->status.permission.key != key)
            continue;
        if ((flags & (ipc_create | ipc_exclusive)) == (ipc_create | ipc_exclusive))
            return -17;
        if (unsigned(count) > set->status.members)
            return -22;
        if (!set->status.permission.allows(current_task()->credentials,
                                           flags | flags >> 3 | flags >> 6))
            return -13;
        return id_for(slot);
    }
    if (key && !(flags & ipc_create))
        return -2;
    if (!count)
        return -22;
    if (empty == max_sets)
        return -28;
    const size_t bytes = sizeof(Set) + count * sizeof(Member);
    auto* set = static_cast<Set*>(alloc(bytes));
    if (!set)
        return -12;
    memset(set, 0, bytes);
    const auto& credentials = current_task()->credentials;
    auto& p = set->status.permission;
    p.key = key;
    p.uid = p.creator_uid = credentials.user.effective;
    p.gid = p.creator_gid = credentials.group.effective;
    p.mode = flags & 0777;
    p.sequence = generations[empty];
    set->status.changed = clock_realtime_ticks() / 100;
    set->status.members = count;
    sets[empty] = set;
    ++live_sets;
    live_members += count;
    return id_for(empty);
}

int operate(int id, uint64_t pointer, unsigned count, uint64_t timeout) {
    if (id < 0 || !count)
        return -22;
    if (count > max_operations)
        return -7;
    auto* request =
        static_cast<SemaphoreRequest*>(alloc(sizeof(SemaphoreRequest) + sizeof(Operation) * count));
    if (!request)
        return -12;
    *request = {nullptr, current_task(), nullptr, nullptr, 0, count, 0};
    auto& memory = current_task()->memory->space;
    int result = [&] {
        const auto* ops = request->operations();
        if (!memory.copy_in(request->operations(), pointer, sizeof(Operation) * count))
            return -14;
        if (timeout) {
            int64_t time[2];
            if (!memory.copy_in(time, timeout, sizeof(time)))
                return -14;
            if (time[0] < 0 || time[1] < 0 || time[1] >= 1000000000)
                return -22;
            const uint64_t fraction = (time[1] + 9999999) / 10000000;
            if (time[0] || time[1]) {
                const uint64_t offset = fraction + 1;
                request->deadline = ticks <= UINT64_MAX - offset &&
                                            uint64_t(time[0]) <= (UINT64_MAX - ticks - offset) / 100
                                        ? ticks + uint64_t(time[0]) * 100 + offset
                                        : UINT64_MAX;
            }
        }
        auto* set = find(id);
        if (!set)
            return -22;
        request->set = set;
        unsigned permissions = 4;
        bool undo = false;
        for (unsigned i = 0; i < count; ++i) {
            if (ops[i].member >= set->status.members)
                return -27;
            if (ops[i].change)
                permissions = 2;
            undo |= bool(ops[i].flags & undo_flag);
        }
        if (!set->status.permission.allows(current_task()->credentials, permissions))
            return -13;
        if (undo && !(request->undo = undo_for(*current_task(), *set)))
            return -12;
        int status = evaluate(*request);
        if (status == 0)
            service(*set);
        if (status == 1 && timeout && !request->deadline)
            return -11;
        return status;
    }();
    if (result != 1) {
        release(request);
        return result;
    }
    auto** link = &request->set->waiting;
    while (*link)
        link = &(*link)->next;
    *link = request;
    current_task()->semaphore_request = request;
    current_task()->wait = Wait::semaphore;
    current_task()->state = State::blocked;
    return would_block;
}

int control(int id, int number, int command, uint64_t argument) {
    auto& memory = current_task()->memory->space;
    if (id < 0)
        return -22;
    if (command == 3 || command == 19) {
        const bool usage = command == 19;
        const int32_t info[] = {1024000000,     max_sets,
                                1024000000,     1024000000,
                                max_members,    max_operations,
                                max_operations, usage ? int32_t(live_sets) : 20,
                                max_value,      usage ? int32_t(live_members) : max_value};
        if (!memory.copy_out(argument, info, sizeof(info)))
            return -14;
        for (unsigned slot = max_sets; slot > 0; --slot)
            if (sets[slot - 1])
                return slot - 1;
        return 0;
    }
    const bool by_slot = command == 18 || command == 20;
    Set* set = by_slot ? (unsigned(id) < max_sets ? sets[id] : nullptr) : find(id);
    if (!set)
        return -22;
    auto& status = set->status;
    const auto& credentials = current_task()->credentials;
    if (command == 0 || command == 1) {
        if (!status.permission.controls(credentials))
            return -1;
        if (command == 0) {
            unsigned slot = unsigned(id) & 32767;
            while (set->waiting)
                complete(*set->waiting->task, -43);
            while (set->adjustments)
                erase_adjustment(set->adjustments);
            --live_sets;
            live_members -= status.members;
            sets[slot] = nullptr;
            ++generations[slot];
            release(set);
            return 0;
        }
        Status input{};
        if (!memory.copy_in(&input, argument, sizeof(input)))
            return -14;
        status.permission.uid = input.permission.uid;
        status.permission.gid = input.permission.gid;
        status.permission.mode = input.permission.mode & 0777;
        status.changed = clock_realtime_ticks() / 100;
        return 0;
    }
    if (command == 2 || by_slot) {
        if (command != 20 && !status.permission.allows(credentials, 4))
            return -13;
        return memory.copy_out(argument, &status, sizeof(status)) ? (by_slot ? id_for(id) : 0)
                                                                  : -14;
    }
    if (command < 11 || command > 17)
        return -22;
    if (!status.permission.allows(credentials, command >= 16 ? 2 : 4))
        return -13;
    if (command == 13 || command == 17) {
        const size_t bytes = status.members * sizeof(uint16_t);
        auto* values = static_cast<uint16_t*>(alloc(bytes));
        if (!values)
            return -12;
        int result = 0;
        if (command == 13) {
            for (unsigned i = 0; i < status.members; ++i)
                values[i] = set->members()[i].value;
            if (!memory.copy_out(argument, values, bytes))
                result = -14;
        } else if (!memory.copy_in(values, argument, bytes))
            result = -14;
        else {
            for (unsigned i = 0; i < status.members; ++i)
                if (values[i] > max_value)
                    result = -34;
            if (!result) {
                for (unsigned i = 0; i < status.members; ++i)
                    set->members()[i] = {values[i], current_task()->process->pid};
                clear_adjustments(*set, 0, status.members);
                status.changed = clock_realtime_ticks() / 100;
                service(*set);
            }
        }
        release(values);
        return result;
    }
    if (unsigned(number) >= status.members)
        return -22;
    auto& member = set->members()[number];
    if (command == 11)
        return member.pid;
    if (command == 12)
        return member.value;
    if (command == 16) {
        int value = int32_t(argument);
        if (value < 0 || value > max_value)
            return -34;
        member = {value, current_task()->process->pid};
        clear_adjustments(*set, number, 1);
        status.changed = clock_realtime_ticks() / 100;
        service(*set);
        return 0;
    }
    int count = 0;
    for (auto* req = set->waiting; req; req = req->next) {
        const auto& op = req->operations()[req->blocked];
        count += op.member == unsigned(number) && (command == 14 ? op.change < 0 : op.change == 0);
    }
    return count;
}
} // namespace

void semaphore_discard(Task& task) {
    auto* request = task.semaphore_request;
    if (!request)
        return;
    auto** link = &request->set->waiting;
    while (*link != request)
        link = &(*link)->next;
    *link = request->next;
    task.semaphore_request = nullptr;
    release(request);
}

bool semaphore_timeout(Task& task) {
    auto* request = task.semaphore_request;
    if (!request || !request->deadline || ticks < request->deadline)
        return false;
    complete(task, -11);
    return true;
}

bool semaphore_share_undo(Task& child, Task& parent) {
    auto* undo = undo_group(parent);
    if (!undo)
        return false;
    child.semaphore_undo = undo;
    ++undo->owners;
    return true;
}

void semaphore_exit(Task& task) {
    semaphore_discard(task);
    auto* undo = task.semaphore_undo;
    task.semaphore_undo = nullptr;
    if (!undo || --undo->owners)
        return;
    while (auto* item = undo->entries) {
        auto& set = *item->set;
        auto* values = item->values();
        for (unsigned i = 0; i < set.status.members; ++i) {
            if (!values[i])
                continue;
            auto& member = set.members()[i];
            int adjusted = member.value + values[i];
            member = {adjusted < 0           ? 0
                      : adjusted > max_value ? max_value
                                             : adjusted,
                      task.process->pid};
        }
        set.status.operated = clock_realtime_ticks() / 100;
        erase_adjustment(item);
        service(set);
    }
    release(undo);
}

int64_t semaphore_syscall(Frame* f) {
    if (f->rax == 64)
        return create(f->rdi, f->rsi, f->rdx);
    if (f->rax == 66)
        return control(f->rdi, f->rsi, f->rdx, f->r10);
    return operate(f->rdi, f->rsi, f->rdx, f->rax == 220 ? f->r10 : 0);
}
} // namespace ax
