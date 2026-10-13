// SPDX-License-Identifier: GPL-3.0-or-later
#include "process/waitid.hpp"

namespace ax {
constexpr unsigned nohang = 1, stopped = 2, exited = 4, continued = 8, nowait = 0x1000000;

struct ChildInformation {
    int32_t signal, error, code, padding;
    int32_t pid;
    uint32_t uid;
    int32_t status, alignment;
    int64_t user_time, system_time;
    uint8_t reserved[80];
};

static_assert(sizeof(ChildInformation) == 128);
constexpr size_t information_bytes = offsetof(ChildInformation, status) + sizeof(int32_t);
static_assert(information_bytes == 28);

int wait_information_selector(const Task& task, unsigned type, uint32_t id, unsigned options,
                              int& selected) {
    if ((options & ~(nohang | stopped | exited | continued | nowait)) ||
        !(options & (stopped | exited | continued)))
        return -22;
    if (type > 2 || (type != 0 && id > INT32_MAX) || (type == 1 && !id))
        return -22; // PID descriptors and traced-child options remain unsupported.
    selected = type == 0 ? 0 : type == 2 && !id ? task.process->pgid : int(id);
    return 0;
}

static bool selected_child(const Task& caller, const Task& child, unsigned type, int selected) {
    return child.state != State::empty && child.process->leader == &child &&
           child.process->parent == caller.process->pid &&
           (type == 0 ||
            (type == 1 ? child.process->pid == selected : child.process->pgid == selected));
}

static unsigned event(const Task& child, unsigned options) {
    if (child.state == State::zombie && !child.process->live_threads)
        return options & exited;
    if (child.process->stopped && !child.process->stop_reported && (options & stopped))
        return stopped;
    return child.process->continued && (options & continued) ? continued : 0;
}

int64_t wait_information(Task& caller, unsigned type, int selected, uint64_t information,
                         unsigned options, uint64_t usage) {
    bool found = false;
    for (auto& child : tasks) {
        if (!selected_child(caller, child, type, selected))
            continue;
        found = true;
        unsigned kind = event(child, options);
        if (!kind)
            continue;
        ChildInformation value{};
        value.signal = 17;
        value.pid = child.process->pid;
        value.uid = child.credentials.user.real;
        if (kind == exited) {
            int status = child.process->exit_status;
            value.code = (status & 0x7f) ? (status & 0x80) ? 3 : 2 : 1;
            value.status = (status & 0x7f) ? status & 0x7f : (status >> 8) & 255;
        } else {
            value.code = kind == stopped ? 5 : 6;
            value.status = kind == stopped ? child.process->stop_signal : 18;
        }
        // Linux consumes the event before copying the result. WNOWAIT keeps it
        // waitable, including when a user output buffer faults.
        if (!(options & nowait)) {
            if (kind == exited)
                reap_task(&child);
            else if (kind == stopped)
                child.process->stop_reported = true;
            else
                child.process->continued = false;
        }
        uint64_t zeros[18]{};
        if ((usage && !caller.memory->space.copy_out(usage, zeros, sizeof(zeros))) ||
            (information && !caller.memory->space.copy_out(information, &value, information_bytes)))
            return -14;
        return 0;
    }
    if (!found)
        return -10;
    if (!(options & nohang))
        return would_block;
    ChildInformation empty{};
    return information && !caller.memory->space.copy_out(information, &empty, information_bytes)
               ? -14
               : 0;
}

bool wait_information_ready(const Task& caller) {
    bool found = false;
    for (const auto& child : tasks)
        if (selected_child(caller, child, unsigned(caller.frame.rdi), caller.wait_pid)) {
            found = true;
            if (event(child, unsigned(caller.frame.r10)))
                return true;
        }
    // A sibling may reap the last selected child while this thread sleeps.
    return !found;
}
} // namespace ax
