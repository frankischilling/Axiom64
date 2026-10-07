// SPDX-License-Identifier: GPL-3.0-or-later
#include "process/futex.hpp"

namespace ax {
struct Key {
    MemoryContext* domain;
    uint64_t identity, page;
    uint32_t* word;
};
static int make_key(Task* task, uint64_t address, bool private_key, Key& key,
                    bool read_word = true) {
    if (address & 3)
        return -22;
    if (address >= user_limit || 4 > user_limit - address)
        return -14;
    if (private_key && !read_word) {
        key = {task->memory, address, 0, nullptr};
        return 0;
    }
    if (!task->memory->space.valid(address, 4))
        return -14;
    auto entry = task->memory->space.entry(address);
    if (*entry & 0x200)
        return -22; // Device mappings cannot own a synchronization word.
    uint64_t page = *entry & page_mask;
    key = {private_key ? task->memory : nullptr,
           private_key ? address : page + address % page_size, page,
           reinterpret_cast<uint32_t*>(static_cast<uint8_t*>(physical(page)) +
                                       address % page_size)};
    return 0;
}
void futex_discard(Task& task) {
    if (task.futex.pinned_page)
        page_free(task.futex.pinned_page);
    task.futex = {};
}
static void complete(Task& task, int result) {
    futex_discard(task);
    // A blocked syscall was saved two bytes before its return address. Complete
    // it here so a signal handler cannot consume a deferred result from a
    // different futex call.
    task.frame.rip += 2;
    task.frame.rax = uint64_t(int64_t(result));
    task.wait = Wait::none;
    if (task.state != State::stopped)
        task.state = State::runnable;
}
static bool matches(const Task& task, const Key& key, uint32_t bitset) {
    return (task.state == State::blocked || task.state == State::stopped) &&
           task.wait == Wait::futex && task.futex.queued &&
           task.futex.domain == key.domain && task.futex.identity == key.identity &&
           (task.futex.bitset & bitset);
}
int futex_wake(Task* caller, uint64_t address, int count, bool private_key, uint32_t bitset) {
    if (!bitset)
        return -22;
    Key key{};
    int error = make_key(caller, address, private_key, key, false);
    if (error)
        return error;
    int woken = 0;
    // Linux's legacy FUTEX_WAKE tests the signed limit after the first wake.
    int limit = count > 0 ? count : 1;
    for (auto& task : tasks)
        if (woken < limit && matches(task, key, bitset)) {
            complete(task, 0);
            woken++;
        }
    return woken;
}
bool futex_ready(Task& task) {
    if (!task.futex.queued || !task.futex.deadline || ticks < task.futex.deadline)
        return false;
    complete(task, -110);
    return true;
}
static uint64_t time_ticks(int64_t sec, int64_t nsec) {
    uint64_t fraction = (nsec + 9999999) / 10000000;
    return uint64_t(sec) > (UINT64_MAX - fraction) / 100
               ? UINT64_MAX
               : uint64_t(sec) * 100 + fraction;
}
int64_t futex_syscall(Frame* frame) {
    uint64_t address = frame->rdi, timeout = frame->r10;
    uint32_t op = frame->rsi, command = op & 127, bitset = frame->r9;
    bool private_key = op & 128;
    if ((op & ~511u) || (command != 0 && command != 1 && command != 3 &&
                        command != 4 && command != 9 && command != 10))
        return -38;
    if ((op & 256) && command != 0 && command != 9)
        return -38;
    if (command == 1 || command == 10)
        return futex_wake(current, address, int(frame->rdx), private_key,
                          command == 10 ? bitset : UINT32_MAX);
    if (command == 3 || command == 4) {
        int wake_count = int(frame->rdx), move_count = int(frame->r10);
        if (wake_count < 0 || move_count < 0)
            return -22;
        Key source{}, target{};
        int error = make_key(current, address, private_key, source, command == 4);
        if (!error)
            error = make_key(current, frame->r8, private_key, target, false);
        if (error)
            return error;
        if (command == 4 && __atomic_load_n(source.word, __ATOMIC_SEQ_CST) != bitset)
            return -11;
        int woken = 0, moved = 0;
        for (auto& task : tasks)
            if (matches(task, source, UINT32_MAX)) {
                if (woken < wake_count) {
                    complete(task, 0);
                    woken++;
                } else if (moved < move_count) {
                    if (!private_key)
                        page_retain(target.page);
                    if (task.futex.pinned_page)
                        page_free(task.futex.pinned_page);
                    task.futex.domain = target.domain;
                    task.futex.identity = target.identity;
                    task.futex.pinned_page = private_key ? 0 : target.page;
                    moved++;
                }
            }
        return woken + moved;
    }
    if (command == 0)
        bitset = UINT32_MAX;
    if (!bitset)
        return -22;
    Key key{};
    int error = make_key(current, address, private_key, key);
    if (error)
        return error;
    uint64_t deadline = 0;
    if (timeout) {
        struct Time {
            int64_t sec, nsec;
        } time;
        if (!current->memory->space.copy_in(&time, timeout, sizeof(time)))
            return -14;
        if (time.sec < 0 || time.nsec < 0 || time.nsec >= 1000000000)
            return -22;
        uint64_t value = time_ticks(time.sec, time.nsec);
        deadline = command == 9 ? value
                                : value > UINT64_MAX - ticks ? UINT64_MAX : ticks + value;
    }
    // SYSCALL masks interrupts; on the current single CPU this read and queue
    // insertion cannot race another userspace writer or wake operation.
    if (__atomic_load_n(key.word, __ATOMIC_SEQ_CST) != uint32_t(frame->rdx))
        return -11;
    if (timeout && deadline <= ticks)
        return -110;
    current->futex = {key.domain, key.identity, private_key ? 0 : key.page, deadline, bitset, true};
    if (!private_key)
        page_retain(key.page);
    current->wait = Wait::futex;
    current->state = State::blocked;
    return would_block;
}
} // namespace ax
