// SPDX-License-Identifier: GPL-3.0-or-later
#include "io/poll.hpp"
#include "ipc/ipc.hpp"
#include "process/signals.hpp"

namespace ax {
struct PollDescriptor {
    int32_t fd;
    uint16_t events, revents;
};

static_assert(sizeof(PollDescriptor) == 8);

struct PollTime {
    int64_t seconds, nanoseconds;
};

struct PollRequest {
    uint64_t descriptors, timeout, start;
    uint32_t count;
    bool finite, ppoll, masked, restart;
    PollTime duration;
    PollDescriptor entries[max_fds];
};

static PollTime remaining(const PollRequest& request) {
    uint64_t elapsed = ticks - request.start;
    int64_t seconds = int64_t(elapsed / 100), nanoseconds = int64_t(elapsed % 100) * 10000000;
    auto left = request.duration;
    if (seconds > left.seconds || (seconds == left.seconds && nanoseconds >= left.nanoseconds))
        return {};
    left.seconds -= seconds;
    left.nanoseconds -= nanoseconds;
    if (left.nanoseconds < 0) {
        --left.seconds;
        left.nanoseconds += 1000000000;
    }
    return left;
}

static bool write_timeout(Task& task, const PollRequest& request) {
    if (!request.timeout || (!request.duration.seconds && !request.duration.nanoseconds))
        return true;
    PollTime left = remaining(request);
    return task.memory->space.copy_out(request.timeout, &left, sizeof(left));
}

static void restore_mask(Task& task, const PollRequest& request) {
    if (request.masked) {
        task.signal_mask = task.suspend_saved_mask;
        task.suspend_mask = false;
    }
}

static int import_descriptors(Task& task, PollRequest& request) {
    if (request.count > max_fds || request.count > task.process->limits.soft(Resource::open_files))
        return -22;
    size_t bytes = request.count * sizeof(PollDescriptor);
    if (request.descriptors > user_limit || bytes > user_limit - request.descriptors)
        return -14;
    return !bytes || task.memory->space.copy_in(request.entries, request.descriptors, bytes) ? 0
                                                                                             : -14;
}

static int write_results(Task& task, const PollRequest& request, int result) {
    for (unsigned i = 0; i < request.count; ++i) {
        uint64_t output =
            request.descriptors + i * sizeof(PollDescriptor) + offsetof(PollDescriptor, revents);
        if (!task.memory->space.copy_out(output, &request.entries[i].revents, sizeof(uint16_t)))
            return -14;
    }
    return result;
}

static int64_t attempt(Task& task, PollRequest& request) {
    unsigned count = 0;
    for (unsigned i = 0; i < request.count; ++i) {
        auto& entry = request.entries[i];
        entry.revents = 0;
        if (entry.fd < 0)
            continue;
        auto handle = unsigned(entry.fd) < max_fds ? task.files->entries[entry.fd].handle : nullptr;
        entry.revents = !handle || (handle->flags & 010000000)
                            ? 32
                            : readiness(handle, &task) & (entry.events | 8 | 16);
        count += entry.revents != 0;
    }
    if (count)
        return write_results(task, request, int(count));
    if (request.finite && !signal_wakes(task)) {
        auto left = remaining(request);
        if (!left.seconds && !left.nanoseconds)
            return write_results(task, request, 0);
    }
    return would_block;
}

int64_t poll_syscall(Task& task, const Frame& frame) {
    PollRequest request{};
    request.ppoll = frame.rax == 271;
    request.descriptors = frame.rdi;
    request.count = uint32_t(frame.rsi);
    request.start = ticks;
    if (request.ppoll) {
        request.timeout = frame.rdx;
        request.finite = request.timeout != 0;
        if (request.finite) {
            auto& duration = request.duration;
            if (!task.memory->space.copy_in(&duration, request.timeout, sizeof(duration)))
                return -14;
            if (duration.seconds < 0 || duration.nanoseconds < 0 ||
                duration.nanoseconds >= 1000000000)
                return -22;
        }
        if (frame.r10) {
            uint64_t mask = 0;
            if (frame.r8 != sizeof(mask))
                return -22;
            if (!task.memory->space.copy_in(&mask, frame.r10, sizeof(mask)))
                return -14;
            request.masked = true;
            task.suspend_saved_mask = task.signal_mask;
            task.suspend_mask = true;
            task.signal_mask = mask & ~unmaskable_signals;
        }
    } else {
        int32_t milliseconds = int32_t(frame.rdx);
        request.finite = milliseconds >= 0;
        if (request.finite)
            request.duration = {milliseconds / 1000, (milliseconds % 1000) * 1000000};
    }

    int64_t result = import_descriptors(task, request);
    if (!result)
        result = attempt(task, request);
    if (result == would_block) {
        auto saved = static_cast<PollRequest*>(alloc(sizeof(PollRequest)));
        if (saved) {
            *saved = request;
            task.poll_request = saved;
            task.wait = Wait::poll;
            task.state = State::blocked;
            return would_block;
        }
        result = -12;
    }
    write_timeout(task, request);
    restore_mask(task, request);
    return result;
}

void poll_discard(Task& task) {
    release(task.poll_request);
    task.poll_request = nullptr;
}

static void complete(Task& task, int result) {
    if (result != -4)
        restore_mask(task, *task.poll_request);
    poll_discard(task);
    task.frame.rip += 2;
    task.frame.rax = uint64_t(result);
    task.wait = Wait::none;
    task.state = State::runnable;
}

bool poll_resume(Task& task) {
    auto request = task.poll_request;
    if (!request)
        return false;
    int64_t result = 0;
    if (request->restart) {
        request->restart = false;
        result = import_descriptors(task, *request);
    }
    if (!result)
        result = attempt(task, *request);
    if (result == would_block)
        return false;
    write_timeout(task, *request);
    complete(task, int(result));
    return true;
}

bool poll_interrupt(Task& task) {
    auto request = task.poll_request;
    if (!request)
        return false;
    int result = write_results(task, *request, -4);
    write_timeout(task, *request);
    // EINTR retains the temporary mask until signal_deliver saves the original mask.
    complete(task, result);
    return true;
}

void poll_stop(Task& task) {
    auto request = task.poll_request;
    if (!request)
        return;
    int error = write_results(task, *request, 0);
    bool wrote = write_timeout(task, *request);
    if (error || !wrote) {
        if (!error)
            restore_mask(task, *request);
        complete(task, error ? error : -4);
    } else if (request->ppoll) {
        // Reenter with the remaining relative time after SIGCONT.
        restore_mask(task, *request);
        poll_discard(task);
        task.wait = Wait::none;
    } else {
        // The restarted poll reimports the array with the original time budget.
        request->restart = true;
    }
}
} // namespace ax
