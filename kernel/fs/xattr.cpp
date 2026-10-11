// SPDX-License-Identifier: GPL-3.0-or-later
#include "fs/xattr.hpp"
#include "fs/vfs.hpp"
#include "process/task.hpp"
#include "security/file_capabilities.hpp"

namespace ax {
namespace {
bool file_caps(const XattrName& name) {
    return name.index == 6 && !strcmp(name.suffix, "capability");
}

int permission(Node* node, const XattrName& name, bool write) {
    if (write && node_readonly(node))
        return -30;
    if (name.index == 6) {
        if (write && current &&
            !capable(current->credentials,
                     file_caps(name) ? Capability::setfcap : Capability::sys_admin))
            return -1;
        return 0;
    }
    if (name.index == 4)
        return !current || capable(current->credentials, Capability::sys_admin) ? 0
               : write                                                          ? -1
                                                                                : -61;
    uint32_t type = node->mode & 0170000;
    if (type != regular_file && type != directory && type != 0140000)
        return write ? -1 : -61;
    if (write && type == directory && (node->mode & 01000) && current &&
        current->credentials.user.filesystem != node->uid &&
        !capable(current->credentials, Capability::fowner))
        return -1;
    return node_access(node, write ? 2 : 4);
}
} // namespace

int64_t node_getxattr(Node* node, const char* key, void* buffer, size_t size) {
    node = file_node(node);
    if (!node || !node->mount->ops->getxattr)
        return -95;
    XattrName name;
    int error = xattr_name(key, name);
    if (!error)
        error = permission(node, name, false);
    if (error)
        return error;
    if (file_caps(name)) {
        uint8_t value[24];
        int64_t length = node->mount->ops->getxattr(node, name, nullptr, 0);
        if (length < 0)
            return length;
        if (length != 12 && length != 20 && length != 24)
            return -22;
        length = node->mount->ops->getxattr(node, name, value, sizeof(value));
        return length < 0 ? length : file_capabilities_export(value, length, buffer, size);
    }
    return node->mount->ops->getxattr(node, name, buffer, size);
}

int64_t node_listxattr(Node* node, void* buffer, size_t size) {
    node = file_node(node);
    if (!node || !node->mount->ops->listxattr)
        return -95;
    return node->mount->ops->listxattr(
        node, buffer, size, !current || capable(current->credentials, Capability::sys_admin));
}

int node_setxattr(Node* node, const char* key, const void* value, size_t size, unsigned flags) {
    if (flags & ~3u)
        return -22;
    if (size > xattr_value_max)
        return -7;
    node = file_node(node);
    if (node && node_readonly(node))
        return -30;
    if (!node || !node->mount->ops->setxattr)
        return -95;
    XattrName name;
    int error = xattr_name(key, name);
    FileCapabilities capabilities;
    if (!error && size && file_caps(name)) {
        error = file_capabilities_decode(value, size, capabilities, FileCapabilityUse::write);
    }
    if (!error)
        error = permission(node, name, true);
    if (!error && size && file_caps(name) && capabilities.root_id == UINT32_MAX)
        error = -22;
    return error ? error : node->mount->ops->setxattr(node, name, value, size, flags);
}

int node_removexattr(Node* node, const char* key) {
    node = file_node(node);
    if (node && node_readonly(node))
        return -30;
    if (!node || !node->mount->ops->removexattr)
        return -95;
    XattrName name;
    int error = xattr_name(key, name);
    if (!error)
        error = permission(node, name, true);
    return error ? error : node->mount->ops->removexattr(node, name);
}

int node_drop_file_capabilities(Node* node) {
    node = file_node(node);
    if (!node || !node->mount->ops->removexattr)
        return 0;
    XattrName name{6, "capability"};
    // A write or ownership transition must remove the marking even when the
    // writer does not have permission to administer file capabilities.
    int error = node->mount->ops->removexattr(node, name);
    return error == -61 || error == -95 ? 0 : error;
}

void node_retire_xattrs(Node* node) {
    node = file_node(node);
    if (node && node->xattrs && !node->links && !node_referenced(node))
        xattr_store_destroy(node->xattrs);
}
} // namespace ax
