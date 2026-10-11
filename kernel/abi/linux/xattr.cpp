// SPDX-License-Identifier: GPL-3.0-or-later
#include "abi/linux/xattr.hpp"
#include "fs/xattr.hpp"
#include "process/task.hpp"

namespace ax {
namespace {
int text(uint64_t address, char* output, size_t capacity, int too_long) {
    auto& space = current->memory->space;
    for (size_t i = 0; i < capacity; i++) {
        if (address > UINT64_MAX - i || !space.copy_in(output + i, address + i, 1))
            return -14;
        if (!output[i])
            return 0;
    }
    return too_long;
}

struct Call {
    Handle* handle = nullptr;
    void* bytes = nullptr;

    ~Call() {
        release(bytes);
        close_handle(handle);
    }
};
} // namespace

int64_t linux_xattr(unsigned number, uint64_t target, uint64_t key, uint64_t data, uint64_t size,
                    uint64_t flags) {
    if (number < 188 || number > 199)
        return -38;
    unsigned operation = (number - 188) / 3, variant = (number - 188) % 3;
    if (!operation && (unsigned(flags) & ~3u))
        return -22;
    if (!operation && size > xattr_value_max)
        return -7;
    char name[256];
    if (operation != 2) {
        int error = text(key, name, sizeof(name), -34);
        if (error)
            return error;
        if (!name[0])
            return -34;
    }
    Call call;
    Node* node = nullptr;
    if (variant == 2) {
        int fd = int(target);
        if (fd < 0 || unsigned(fd) >= max_fds)
            return -9;
        auto handle = current->files->entries[fd].handle;
        if (!handle || (handle->flags & 010000000)) // O_PATH is not an xattr descriptor.
            return -9;
        if (!handle->node)
            return -95;
        retain(handle);
        call.handle = handle;
        node = handle->node;
    } else {
        Path path;
        int error = text(target, path.text, sizeof(path.text), -36);
        if (error)
            return error;
        if (!path.text[0])
            return -2;
        path.base = path.text[0] == '/' ? current->fs->root_node : current->fs->cwd_node;
        path.error = 0;
        error = resolve_path(path, node, variant != 1);
        if (error)
            return error;
    }
    if (operation == 3)
        return node_removexattr(node, name);
    if (operation == 2) {
        size = data;
        data = key;
    }
    size_t capacity = min(uint64_t(xattr_value_max), size);
    if (capacity) {
        call.bytes = alloc(capacity);
        if (!call.bytes)
            return -12;
    }
    if (!operation) {
        if (capacity && !current->memory->space.copy_in(call.bytes, data, capacity))
            return -14;
        return node_setxattr(node, name, call.bytes, capacity, flags);
    }
    int64_t result = operation == 1 ? node_getxattr(node, name, call.bytes, capacity)
                                    : node_listxattr(node, call.bytes, capacity);
    if (result > 0 && capacity && !current->memory->space.copy_out(data, call.bytes, result))
        return -14;
    return result == -34 && capacity == xattr_value_max ? -7 : result;
}
} // namespace ax
