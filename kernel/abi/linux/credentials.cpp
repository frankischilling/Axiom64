// SPDX-License-Identifier: GPL-3.0-or-later
#include "abi/linux/credentials.hpp"
#include "process/task.hpp"

namespace ax {
namespace {
void commit(const Credentials& proposed) {
    auto& cred = current->credentials;
    if (cred.user.effective != proposed.user.effective ||
        cred.user.filesystem != proposed.user.filesystem ||
        cred.group.effective != proposed.group.effective ||
        cred.group.filesystem != proposed.group.filesystem ||
        (proposed.permitted & ~cred.permitted))
        current->memory->dumpable = false;
    cred = proposed;
}

int change(bool group, IdentityChange method, uint32_t a, uint32_t b = UINT32_MAX,
           uint32_t c = UINT32_MAX) {
    auto proposed = current->credentials;
    int error = credential_identity(proposed, group, method, a, b, c);
    if (!error)
        commit(proposed);
    return error;
}

struct CapabilityHeader {
    uint32_t version;
    int32_t pid;
};

struct CapabilityData {
    uint32_t effective, permitted, inheritable;
};

int64_t capabilities(Frame* frame) {
    auto& space = current->memory->space;
    CapabilityHeader header;
    if (!space.copy_in(&header, frame->rdi, sizeof(header)))
        return -14;
    unsigned words = header.version == 0x19980330                                   ? 1
                     : header.version == 0x20071026 || header.version == 0x20080522 ? 2
                                                                                    : 0;
    if (!words) {
        uint32_t version = 0x20080522;
        if (!space.copy_out(frame->rdi, &version, sizeof(version)))
            return -14;
        return frame->rax == 125 && !frame->rsi ? 0 : -22;
    }
    CapabilityData data[2]{};
    if (frame->rax == 125) {
        if (!frame->rsi)
            return 0;
        const Credentials* cred = nullptr;
        if (!header.pid)
            cred = &current->credentials;
        else if (header.pid < 0)
            return -22;
        else
            for (auto& task : tasks)
                if (task.state != State::empty && task.pid == header.pid)
                    cred = &task.credentials;
        if (!cred)
            return -3;
        for (unsigned at = 0; at < words; at++)
            data[at] = {uint32_t(cred->effective >> (32 * at)),
                        uint32_t(cred->permitted >> (32 * at)),
                        uint32_t(cred->inheritable >> (32 * at))};
        return space.copy_out(frame->rsi, data, words * sizeof(data[0])) ? 0 : -14;
    }
    if (header.pid && header.pid != current->pid)
        return -1;
    if (!space.copy_in(data, frame->rsi, words * sizeof(data[0])))
        return -14;
    auto proposed = current->credentials;
    int result =
        credential_capabilities(proposed, data[0].effective | (uint64_t(data[1].effective) << 32),
                                data[0].permitted | (uint64_t(data[1].permitted) << 32),
                                data[0].inheritable | (uint64_t(data[1].inheritable) << 32));
    if (!result)
        commit(proposed);
    return result;
}
} // namespace

int64_t credential_syscall(Frame* frame) {
    auto& cred = current->credentials;
    auto& space = current->memory->space;
    uint32_t a = frame->rdi, b = frame->rsi, c = frame->rdx;
    switch (frame->rax) {
    case 102:
        return cred.user.real;
    case 104:
        return cred.group.real;
    case 107:
        return cred.user.effective;
    case 108:
        return cred.group.effective;
    case 105:
    case 106:
        return change(frame->rax == 106, IdentityChange::single, a);
    case 113:
    case 114:
        return change(frame->rax == 114, IdentityChange::real_effective, a, b);
    case 117:
    case 119:
        return change(frame->rax == 119, IdentityChange::real_effective_saved, a, b, c);
    case 118:
    case 120: {
        const auto& id = frame->rax == 120 ? cred.group : cred.user;
        return space.copy_out(frame->rdi, &id.real, sizeof(id.real)) &&
                       space.copy_out(frame->rsi, &id.effective, sizeof(id.effective)) &&
                       space.copy_out(frame->rdx, &id.saved, sizeof(id.saved))
                   ? 0
                   : -14;
    }
    case 122:
    case 123: {
        auto proposed = cred;
        uint32_t previous = credential_filesystem(proposed, frame->rax == 123, a);
        commit(proposed);
        return previous;
    }
    case 115: {
        if (int32_t(a) < 0)
            return -22;
        unsigned count = cred.groups ? cred.groups->count : 0;
        if (a && a < count)
            return -22;
        if (a && count && !space.copy_out(frame->rsi, cred.groups->ids, size_t(count) * 4))
            return -14;
        return count;
    }
    case 116: {
        if (!capable(cred, Capability::setgid))
            return -1;
        if (a > maximum_groups)
            return -22;
        auto list = groups_allocate(a);
        if (!list)
            return -12;
        int result = a && !space.copy_in(list->ids, frame->rsi, size_t(a) * 4)
                         ? -14
                         : credential_groups(cred, list);
        groups_release(list);
        return result;
    }
    case 125:
    case 126:
        return capabilities(frame);
    case 157:
        if (a == 3)
            return current->memory->dumpable;
        if (a == 4) {
            if (frame->rsi > 1)
                return -22;
            current->memory->dumpable = frame->rsi;
            return 0;
        }
        return credential_control(cred, a, frame->rsi, frame->rdx, frame->r10, frame->r8);
    default:
        return -38;
    }
}
} // namespace ax
