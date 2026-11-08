// SPDX-License-Identifier: GPL-3.0-or-later
#include "ipc/unix_credentials.hpp"
#include "process/task.hpp"

namespace ax {
namespace {
struct Header {
    uint64_t length;
    int32_t level, type;
};

struct MessageIdentity {
    int32_t pid;
    uint32_t uid, gid;
};

static_assert(sizeof(Header) == 16 && sizeof(MessageIdentity) == 12);

bool matches(const ax::Identity& identity, uint32_t value) {
    return value == identity.real || value == identity.effective || value == identity.saved;
}

int authorize(const Task& task, const MessageIdentity& value) {
    if (value.uid == UINT32_MAX || value.gid == UINT32_MAX)
        return -22;
    const auto& credentials = task.credentials;
    if ((value.pid != task.process->pid && !capable(credentials, Capability::sys_admin)) ||
        (!matches(credentials.user, value.uid) && !capable(credentials, Capability::setuid)) ||
        (!matches(credentials.group, value.gid) && !capable(credentials, Capability::setgid)))
        return -1;
    for (const auto& candidate : tasks)
        if (candidate.state != State::empty && candidate.pid == value.pid)
            return 0;
    return -3;
}

bool output(Task& task, uint64_t pointer, const void* data, size_t length) {
    auto bytes = static_cast<const uint8_t*>(data);
    if (pointer >= user_limit || length > user_limit - pointer)
        return false;
    while (length) {
        size_t count = min(length, size_t(page_size - pointer % page_size));
        if (!task.memory->space.copy_out(pointer, bytes, count))
            return false;
        pointer += count;
        bytes += count;
        length -= count;
    }
    return true;
}
} // namespace

int UnixMessageCredentials::read(Task& task, uint64_t pointer, size_t length) {
    if (!length)
        return 0;
    if (length > 0x7fffffff)
        return -105;

    struct Copy {
        uint8_t* bytes;

        ~Copy() {
            release(bytes);
        }
    } copy{static_cast<uint8_t*>(alloc(length))};

    if (!copy.bytes)
        return -12;
    if (!task.memory->space.copy_in(copy.bytes, pointer, length))
        return -14;
    size_t offset = 0;
    while (length - offset >= sizeof(Header)) {
        Header header;
        memcpy(&header, copy.bytes + offset, sizeof(header));
        if (header.length < sizeof(Header) || header.length > length - offset)
            return -22;
        if (header.level == 1) {
            if (header.type == 1) {
                if (header.length >= sizeof(Header) + sizeof(int32_t))
                    return -95;
            } else if (header.type == 2) {
                if (header.length != sizeof(Header) + sizeof(MessageIdentity))
                    return -22;
                MessageIdentity value;
                memcpy(&value, copy.bytes + offset + sizeof(Header), sizeof(value));
                if (int error = authorize(task, value))
                    return error;
                pid = value.pid;
                uid = value.uid;
                gid = value.gid;
                captured = true;
            } else
                return -22;
        }
        size_t aligned = (header.length + 7) & ~size_t(7);
        if (aligned > length - offset)
            break;
        offset += aligned;
    }
    return 0;
}

void UnixMessageCredentials::capture(const Task& task) {
    if (captured)
        return;
    pid = task.process->pid;
    uid = task.credentials.user.real;
    gid = task.credentials.group.real;
    captured = true;
}

size_t UnixMessageCredentials::write(Task& task, uint64_t pointer, size_t capacity,
                                     uint32_t& flags) const {
    if (!pointer || capacity < sizeof(Header)) {
        flags |= 8;
        return 0;
    }
    size_t count = min(capacity, sizeof(Header) + sizeof(MessageIdentity));
    if (count < sizeof(Header) + sizeof(MessageIdentity))
        flags |= 8;
    Header header{count, 1, 2};
    MessageIdentity value{pid, uid, gid};
    // Ancillary output faults leave the payload result intact. Only a complete
    // control write advances msg_controllen; peeking still retains the record.
    if (!output(task, pointer, &header.length, 8) || !output(task, pointer + 8, &header.level, 4) ||
        !output(task, pointer + 12, &header.type, 4) ||
        !output(task, pointer + sizeof(Header), &value, count - sizeof(Header)))
        return 0;
    return min(capacity, size_t(32));
}
} // namespace ax
