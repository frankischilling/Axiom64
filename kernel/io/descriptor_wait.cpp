// SPDX-License-Identifier: GPL-3.0-or-later
#include "io/descriptor_wait.hpp"
#include "ipc/ipc.hpp"
#include "process/signals.hpp"

namespace ax {
enum class WaitCall { poll, ppoll, select, pselect };

struct PollDescriptor {
    int32_t fd;
    uint16_t events, revents;
};

struct WaitTime {
    int64_t seconds, fraction;
};

static_assert(sizeof(PollDescriptor) == 8 && sizeof(WaitTime) == 16);

constexpr unsigned bitmap_words = (max_fds + 63) / 64;

struct DescriptorWait {
    WaitCall call;
    uint64_t descriptors, timeout, start;
    uint32_t count;
    bool finite, masked, restart;
    WaitTime duration;
    PollDescriptor entries[max_fds];
    uint64_t set_pointers[3], sets[3][bitmap_words];

    bool uses_bitmaps() const {
        return call == WaitCall::select || call == WaitCall::pselect;
    }

    size_t bitmap_bytes() const {
        return (count + 63) / 64 * sizeof(uint64_t);
    }
};

static WaitTime remaining(const DescriptorWait& wait) {
    uint64_t elapsed = ticks - wait.start;
    int64_t seconds = int64_t(elapsed / 100), nanoseconds = int64_t(elapsed % 100) * 10000000;
    auto left = wait.duration;
    if (seconds > left.seconds || (seconds == left.seconds && nanoseconds >= left.fraction))
        return {};
    left.seconds -= seconds;
    left.fraction -= nanoseconds;
    if (left.fraction < 0) {
        --left.seconds;
        left.fraction += 1000000000;
    }
    return left;
}

static bool write_timeout(Task& task, const DescriptorWait& wait) {
    if (!wait.timeout || (!wait.duration.seconds && !wait.duration.fraction))
        return true;
    auto left = remaining(wait);
    if (wait.call == WaitCall::select)
        left.fraction /= 1000;
    return task.memory->space.copy_out(wait.timeout, &left, sizeof(left));
}

static void restore_mask(Task& task, const DescriptorWait& wait) {
    if (wait.masked) {
        task.signal_mask = task.suspend_saved_mask;
        task.suspend_mask = false;
    }
}

static int import_poll(Task& task, DescriptorWait& wait) {
    if (wait.count > max_fds || wait.count > task.process->limits.soft(Resource::open_files))
        return -22;
    size_t bytes = wait.count * sizeof(PollDescriptor);
    if (wait.descriptors > user_limit || bytes > user_limit - wait.descriptors)
        return -14;
    return !bytes || task.memory->space.copy_in(wait.entries, wait.descriptors, bytes) ? 0 : -14;
}

static int import_select(Task& task, DescriptorWait& wait, int32_t count) {
    if (count < 0)
        return -22;
    wait.count = min(unsigned(count), task.files->capacity);
    size_t bytes = wait.bitmap_bytes();
    for (unsigned set = 0; set < 3; ++set)
        if (wait.set_pointers[set] && bytes &&
            !task.memory->space.copy_in(wait.sets[set], wait.set_pointers[set], bytes))
            return -14;
    for (unsigned fd = 0; fd < wait.count; ++fd) {
        unsigned word = fd / 64;
        uint64_t selected = wait.sets[0][word] | wait.sets[1][word] | wait.sets[2][word];
        auto& descriptor = task.files->entries[fd];
        if ((selected & (1ull << (fd % 64))) && !descriptor.handle && !descriptor.reserved)
            return -9;
    }
    return 0;
}

static int write_poll(Task& task, const DescriptorWait& wait, int result) {
    for (unsigned i = 0; i < wait.count; ++i) {
        uint64_t output =
            wait.descriptors + i * sizeof(PollDescriptor) + offsetof(PollDescriptor, revents);
        if (!task.memory->space.copy_out(output, &wait.entries[i].revents, sizeof(uint16_t)))
            return -14;
    }
    return result;
}

static uint32_t descriptor_events(Task& task, unsigned fd) {
    auto handle = fd < max_fds ? task.files->entries[fd].handle : nullptr;
    return !handle || (handle->flags & 010000000) ? 32 : readiness(handle, &task);
}

static bool expired(const DescriptorWait& wait, const Task& task) {
    if (!wait.finite)
        return false;
    auto left = remaining(wait);
    return !left.seconds && !left.fraction && !signal_wakes(task);
}

static int64_t attempt_poll(Task& task, DescriptorWait& wait) {
    unsigned count = 0;
    for (unsigned i = 0; i < wait.count; ++i) {
        auto& entry = wait.entries[i];
        entry.revents = entry.fd < 0 ? 0
                                     : descriptor_events(task, unsigned(entry.fd)) &
                                           (entry.events | 8 | 16 | 32);
        count += entry.revents != 0;
    }
    if (count || expired(wait, task))
        return write_poll(task, wait, int(count));
    return would_block;
}

static int64_t attempt_select(Task& task, const DescriptorWait& wait) {
    // Read, write and exceptional conditions each contribute one result bit.
    constexpr uint32_t events[] = {1 | 8 | 16 | 32 | 0x40 | 0x80, 4 | 8 | 32 | 0x100 | 0x200,
                                   2 | 32};
    uint64_t output[3][bitmap_words]{};
    int count = 0;
    for (unsigned fd = 0; fd < wait.count; ++fd) {
        unsigned word = fd / 64;
        uint64_t bit = 1ull << (fd % 64);
        if (!((wait.sets[0][word] | wait.sets[1][word] | wait.sets[2][word]) & bit))
            continue;
        uint32_t ready = descriptor_events(task, fd);
        for (unsigned set = 0; set < 3; ++set)
            if ((wait.sets[set][word] & bit) && (ready & events[set])) {
                output[set][word] |= bit;
                ++count;
            }
    }
    if (!count && !expired(wait, task))
        return would_block;
    size_t bytes = wait.bitmap_bytes();
    for (unsigned set = 0; set < 3; ++set)
        if (wait.set_pointers[set] && bytes &&
            !task.memory->space.copy_out(wait.set_pointers[set], output[set], bytes))
            return -14;
    return count;
}

static int64_t attempt(Task& task, DescriptorWait& wait) {
    return wait.uses_bitmaps() ? attempt_select(task, wait) : attempt_poll(task, wait);
}

static int import_timeout(Task& task, DescriptorWait& wait, const Frame& frame) {
    auto& time = wait.duration;
    if (wait.call == WaitCall::poll) {
        int32_t milliseconds = int32_t(frame.rdx);
        wait.finite = milliseconds >= 0;
        if (wait.finite)
            time = {milliseconds / 1000, (milliseconds % 1000) * 1000000};
        return 0;
    }

    wait.timeout = wait.uses_bitmaps() ? frame.r8 : frame.rdx;
    wait.finite = wait.timeout != 0;
    if (!wait.finite)
        return 0;
    if (!task.memory->space.copy_in(&time, wait.timeout, sizeof(time)))
        return -14;
    if (wait.call == WaitCall::select) {
        // The timeval syscall normalizes whole seconds carried in tv_usec.
        time.seconds = int64_t(uint64_t(time.seconds) + uint64_t(time.fraction / 1000000));
        time.fraction = (time.fraction % 1000000) * 1000;
    }
    return time.seconds < 0 || time.fraction < 0 || time.fraction >= 1000000000 ? -22 : 0;
}

static int import_mask(Task& task, DescriptorWait& wait, uint64_t pointer, uint64_t size) {
    if (!pointer)
        return 0;
    uint64_t mask;
    if (size != sizeof(mask))
        return -22;
    if (!task.memory->space.copy_in(&mask, pointer, sizeof(mask)))
        return -14;
    wait.masked = true;
    task.suspend_saved_mask = task.signal_mask;
    task.suspend_mask = true;
    task.signal_mask = mask & ~unmaskable_signals;
    return 0;
}

int64_t descriptor_wait_syscall(Task& task, const Frame& frame) {
    DescriptorWait wait{};
    if (frame.rax == 23)
        wait.call = WaitCall::select;
    else if (frame.rax == 270)
        wait.call = WaitCall::pselect;
    else if (frame.rax == 271)
        wait.call = WaitCall::ppoll;

    uint64_t mask[2]{};
    if (wait.call == WaitCall::pselect && frame.r9 &&
        !task.memory->space.copy_in(mask, frame.r9, sizeof(mask)))
        return -14;
    if (wait.call == WaitCall::ppoll) {
        mask[0] = frame.r10;
        mask[1] = frame.r8;
    }
    wait.start = ticks;
    if (int error = import_timeout(task, wait, frame))
        return error;
    if (int error = import_mask(task, wait, mask[0], mask[1]))
        return error;
    int64_t result;
    if (wait.uses_bitmaps()) {
        wait.set_pointers[0] = frame.rsi;
        wait.set_pointers[1] = frame.rdx;
        wait.set_pointers[2] = frame.r10;
        result = import_select(task, wait, int32_t(frame.rdi));
    } else {
        wait.descriptors = frame.rdi;
        wait.count = uint32_t(frame.rsi);
        result = import_poll(task, wait);
    }
    if (!result)
        result = attempt(task, wait);
    if (result == would_block) {
        auto saved = static_cast<DescriptorWait*>(alloc(sizeof(DescriptorWait)));
        if (saved) {
            *saved = wait;
            task.descriptor_wait = saved;
            task.wait = Wait::descriptor;
            task.state = State::blocked;
            return would_block;
        }
        result = -12;
    }
    write_timeout(task, wait);
    restore_mask(task, wait);
    return result;
}

void descriptor_wait_discard(Task& task) {
    release(task.descriptor_wait);
    task.descriptor_wait = nullptr;
}

static void complete(Task& task, int result) {
    if (result != -4)
        restore_mask(task, *task.descriptor_wait);
    descriptor_wait_discard(task);
    task.frame.rip += 2;
    task.frame.rax = uint64_t(result);
    task.wait = Wait::none;
    task.state = State::runnable;
}

bool descriptor_wait_resume(Task& task) {
    auto wait = task.descriptor_wait;
    if (!wait)
        return false;
    int64_t result = 0;
    if (wait->restart) {
        wait->restart = false;
        result = import_poll(task, *wait);
    }
    if (!result)
        result = attempt(task, *wait);
    if (result == would_block)
        return false;
    write_timeout(task, *wait);
    complete(task, int(result));
    return true;
}

bool descriptor_wait_interrupt(Task& task) {
    auto wait = task.descriptor_wait;
    if (!wait)
        return false;
    int result = wait->uses_bitmaps() ? -4 : write_poll(task, *wait, -4);
    write_timeout(task, *wait);
    // EINTR retains the temporary mask until signal_deliver saves the original mask.
    complete(task, result);
    return true;
}

void descriptor_wait_stop(Task& task) {
    auto wait = task.descriptor_wait;
    if (!wait)
        return;
    int error = wait->uses_bitmaps() ? 0 : write_poll(task, *wait, 0);
    bool wrote = write_timeout(task, *wait);
    if (error || !wrote) {
        if (!error)
            restore_mask(task, *wait);
        complete(task, error ? error : -4);
    } else if (wait->call == WaitCall::poll) {
        // The restarted poll reimports the array with the original time budget.
        wait->restart = true;
    } else {
        // Reimport the inputs and remaining relative time on SIGCONT.
        restore_mask(task, *wait);
        descriptor_wait_discard(task);
        task.wait = Wait::none;
    }
}
} // namespace ax
