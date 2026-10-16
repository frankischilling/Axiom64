// SPDX-License-Identifier: GPL-3.0-or-later
#include "fs/record_lock.hpp"
#include "process/task.hpp"

namespace ax {
constexpr size_t record_limit = 2048;

struct Record {
    Node* node;
    FileTable* table;
    Handle* description;
    uint64_t first, last;
    int pid;
    bool write;
};

struct RecordWait {
    Task* task;
    Record request;
};

static Record records[record_limit], pending_records[record_limit + 2];
static size_t record_count;
static RecordWait waits[max_tasks];

bool record_lock_command(uint64_t command) {
    return (command >= 5 && command <= 7) || (command >= 36 && command <= 38);
}

static bool ofd(unsigned command) {
    return command >= 36;
}

static bool query(unsigned command) {
    return command == 5 || command == 36;
}

static bool blocking(unsigned command) {
    return command == 7 || command == 38;
}

int record_lock_prepare(Handle* handle, unsigned command, RecordFlock& lock) {
    if (!record_lock_command(command))
        return -22;
    if (!handle || (handle->flags & 010000000))
        return -9;
    if (!handle->node)
        return -95;
    if (lock.type < 0 || lock.type > 2 || (query(command) && lock.type == 2) || lock.whence < 0 ||
        lock.whence > 2 || (ofd(command) && lock.pid))
        return -22;
    if (!query(command) && lock.type != 2 &&
        ((lock.type == 0 && (handle->flags & 3) == 1) ||
         (lock.type == 1 && (handle->flags & 3) == 0)))
        return -9;
    uint64_t base = lock.whence == 0 ? 0 : lock.whence == 1 ? handle->offset : handle->node->size;
    if (base > INT64_MAX)
        return -75;
    uint64_t first;
    if (lock.start < 0) {
        uint64_t distance = uint64_t(-(lock.start + 1)) + 1;
        if (distance > base)
            return -22;
        first = base - distance;
    } else {
        if (uint64_t(lock.start) > uint64_t(INT64_MAX) - base)
            return -75;
        first = base + uint64_t(lock.start);
    }
    if (lock.length < 0) {
        uint64_t size = uint64_t(-(lock.length + 1)) + 1;
        if (size > first)
            return -22;
        first -= size;
        if (size > INT64_MAX)
            return -75;
        lock.length = int64_t(size);
    }
    if (lock.length && uint64_t(lock.length - 1) > uint64_t(INT64_MAX) - first)
        return -75;
    lock.start = int64_t(first);
    lock.whence = 0;
    return 0;
}

static bool owner(const Record& first, const Record& second) {
    return first.table == second.table && first.description == second.description;
}

static bool overlap(const Record& first, const Record& second) {
    return first.first <= second.last && second.first <= first.last;
}

static bool conflict(const Record& first, const Record& second) {
    return first.node == second.node && !owner(first, second) && overlap(first, second) &&
           (first.write || second.write);
}

void record_lock_discard(Task& task) {
    for (auto& wait : waits)
        if (wait.task == &task)
            wait = {};
}

static bool deadlock(FileTable* from, FileTable* target, FileTable* visited[max_tasks],
                     size_t& count) {
    if (from == target)
        return true;
    for (size_t i = 0; i < count; i++)
        if (visited[i] == from)
            return false;
    if (count == max_tasks)
        return false;
    visited[count++] = from;
    for (const auto& wait : waits) {
        if (!wait.task || wait.request.table != from)
            continue;
        for (size_t i = 0; i < record_count; i++)
            if (records[i].table && conflict(records[i], wait.request) &&
                deadlock(records[i].table, target, visited, count))
                return true;
    }
    return false;
}

static int retain_wait(Task& task, const Record& request) {
    if (request.table)
        for (size_t i = 0; i < record_count; i++) {
            if (!records[i].table || !conflict(records[i], request))
                continue;
            FileTable* visited[max_tasks]{};
            size_t count = 0;
            if (deadlock(records[i].table, request.table, visited, count))
                return -35;
        }
    for (auto& wait : waits)
        if (!wait.task) {
            wait = {&task, request};
            return -11;
        }
    return -37;
}

int record_lock_try(Task& task, Handle* handle, unsigned command, RecordFlock& lock) {
    record_lock_discard(task);
    Record request{file_node(handle->node),
                   ofd(command) ? nullptr : task.files,
                   ofd(command) ? handle : nullptr,
                   uint64_t(lock.start),
                   lock.length ? uint64_t(lock.start) + uint64_t(lock.length) - 1
                               : uint64_t(INT64_MAX),
                   ofd(command) ? -1 : task.process->pid,
                   lock.type == 1};
    if (lock.type != 2)
        for (size_t i = 0; i < record_count; i++) {
            if (!conflict(records[i], request))
                continue;
            if (query(command)) {
                lock.type = records[i].write ? 1 : 0;
                lock.whence = 0;
                lock.start = int64_t(records[i].first);
                lock.length = records[i].last == INT64_MAX
                                  ? 0
                                  : int64_t(records[i].last - records[i].first + 1);
                lock.pid = records[i].pid;
                return 0;
            }
            return blocking(command) ? retain_wait(task, request) : -11;
        }
    if (query(command)) {
        lock.type = 2;
        return 0;
    }
    size_t next_count = 0;
    for (size_t i = 0; i < record_count; i++) {
        const auto& old = records[i];
        if (old.node == request.node && owner(old, request) && overlap(old, request)) {
            if (old.first < request.first) {
                auto left = old;
                left.last = request.first - 1;
                pending_records[next_count++] = left;
            }
            if (old.last > request.last) {
                auto right = old;
                right.first = request.last + 1;
                pending_records[next_count++] = right;
            }
        } else
            pending_records[next_count++] = old;
    }
    if (lock.type != 2) {
        bool merged;
        do {
            merged = false;
            for (size_t i = 0; i < next_count; i++) {
                const auto& old = pending_records[i];
                if (old.node != request.node || !owner(old, request) ||
                    old.write != request.write ||
                    old.first > request.last + (request.last != INT64_MAX) ||
                    request.first > old.last + (old.last != INT64_MAX))
                    continue;
                request.first = min(request.first, old.first);
                request.last = max(request.last, old.last);
                pending_records[i] = pending_records[--next_count];
                merged = true;
                break;
            }
        } while (merged);
        pending_records[next_count++] = request;
    }
    if (next_count > record_limit)
        return -37;
    memcpy(records, pending_records, next_count * sizeof(Record));
    record_count = next_count;
    return 0;
}

void record_lock_close(FileTable& table, Node* node) {
    node = file_node(node);
    for (size_t i = 0; i < record_count;)
        if (records[i].table == &table && records[i].node == node)
            records[i] = records[--record_count];
        else
            i++;
}

void record_lock_release(FileTable& table) {
    for (size_t i = 0; i < record_count;)
        if (records[i].table == &table)
            records[i] = records[--record_count];
        else
            i++;
}

void record_lock_release(Handle& handle) {
    for (size_t i = 0; i < record_count;)
        if (records[i].description == &handle)
            records[i] = records[--record_count];
        else
            i++;
}
} // namespace ax
