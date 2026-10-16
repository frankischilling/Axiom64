// SPDX-License-Identifier: GPL-3.0-or-later
#include "abi/linux/resource.hpp"
#include "process/task.hpp"

namespace ax {
namespace {
bool permitted(const Task& target) {
    if (&target == current || capable(current->credentials, Capability::sys_resource))
        return true;
    const auto& from = current->credentials;
    const auto& to = target.credentials;
    return from.user.real == to.user.real && from.user.real == to.user.effective &&
           from.user.real == to.user.saved && from.group.real == to.group.real &&
           from.group.real == to.group.effective && from.group.real == to.group.saved;
}
} // namespace

int64_t resource_syscall(Frame* frame) {
    auto& space = current->memory->space;
    Task* target = current;
    unsigned resource = uint32_t(frame->rdi);
    uint64_t input = frame->rax == 160 ? frame->rsi : 0;
    uint64_t output = frame->rax == 97 ? frame->rsi : 0;
    if (frame->rax == 302) {
        resource = uint32_t(frame->rsi);
        input = frame->rdx;
        output = frame->r10;
    }
    ResourceLimit replacement{}, previous{};
    if (input && !space.copy_in(&replacement, input, sizeof(replacement)))
        return -14;
    if (frame->rax == 160 && !input)
        return -14;
    if (frame->rax == 302 && int32_t(frame->rdi)) {
        target = nullptr;
        for (auto& task : tasks)
            if (task.state != State::empty && task.pid == int32_t(frame->rdi))
                target = &task;
        if (!target)
            return -3;
        if (!permitted(*target))
            return -1;
    }
    int error =
        target->process->limits.exchange(resource, input ? &replacement : nullptr, &previous,
                                         capable(current->credentials, Capability::sys_resource));
    if (error)
        return error;
    if (frame->rax == 97 && !output)
        return -14;
    return output && !space.copy_out(output, &previous, sizeof(previous)) ? -14 : 0;
}
} // namespace ax
