// SPDX-License-Identifier: GPL-3.0-or-later
#include "vfs.hpp"
#include "devices.hpp"
#include "ipc.hpp"
#include "task.hpp"
#include "block.hpp"

namespace ax {
Timestamp node_now() {
    return {int64_t(ticks / 100), (ticks % 100) * 10000000};
}
Node nodes[16384];
size_t node_count;
Node* root_node;
static Handle handles[1024];
static uint64_t next_generation = 1;

bool normalize(const char* cwd, const char* path, char* result, size_t cap) {
    char input[2048];
    size_t n = 0;
    if (!path || !*path || cap < 2)
        return false;
    if (*path != '/') {
        size_t k = strlen(cwd);
        if (k + 1 >= sizeof(input))
            return false;
        memcpy(input, cwd, k);
        n = k;
        input[n++] = '/';
    }
    size_t k = strlen(path);
    if (n + k >= sizeof(input))
        return false;
    memcpy(input + n, path, k + 1);
    size_t output = 1;
    result[0] = '/';
    for (size_t p = 0; input[p];) {
        while (input[p] == '/')
            p++;
        size_t begin = p;
        while (input[p] && input[p] != '/')
            p++;
        size_t len = p - begin;
        if (!len)
            break;
        if (len == 1 && input[begin] == '.')
            continue;
        if (len == 2 && input[begin] == '.' && input[begin + 1] == '.') {
            while (output > 1 && result[output - 1] != '/')
                output--;
            if (output > 1)
                output--;
            continue;
        }
        if (output > 1) {
            if (output + 1 >= cap)
                return false;
            result[output++] = '/';
        }
        if (output + len >= cap)
            return false;
        memcpy(result + output, input + begin, len);
        output += len;
    }
    result[output] = 0;
    return true;
}
static Mount mounts[16];
static uint64_t next_mount_id = 1;
static Mount* mounted_on(Node* point) {
    for (auto& mount : mounts)
        if (mount.active && mount.point == point)
            return &mount;
    return nullptr;
}
Node* directory_parent(Node* node) {
    if (node == node->mount->root && node->mount->point)
        return node->mount->point->parent;
    return node->parent ? node->parent : node;
}
void node_path(Node* node, char* result, size_t cap) {
    if (!cap)
        return;
    result[0] = 0;
    Node* chain[128];
    size_t count = 0;
    while (node && node != root_node && count < 128) {
        if (node == node->mount->root && node->mount->point) {
            node = node->mount->point;
            continue;
        }
        if (node->removed)
            return;
        chain[count++] = node;
        node = node->parent;
    }
    if (node != root_node)
        return;
    size_t offset = 0;
    if (!count) {
        if (cap >= 2) {
            result[0] = '/';
            result[1] = 0;
        }
        return;
    }
    while (count) {
        auto part = chain[--count];
        size_t len = strlen(part->name);
        if (offset + len + 1 >= cap) {
            result[0] = 0;
            return;
        }
        result[offset++] = '/';
        memcpy(result + offset, part->name, len);
        offset += len;
    }
    result[offset] = 0;
}
int resolve_path(const Path& path, Node*& result, bool follow) {
    result = nullptr;
    if (!path.text[0])
        return -2;
    char pending[2048];
    memcpy(pending, path.text, strlen(path.text) + 1);
    Node* node = pending[0] == '/' ? root_node : path.base;
    if (!node)
        return -2;
    unsigned links = 0;
    size_t p = 0;
    while (pending[p]) {
        while (pending[p] == '/')
            p++;
        if ((node->mode & 0170000) != directory)
            return -20;
        if (!pending[p])
            break;
        size_t begin = p;
        while (pending[p] && pending[p] != '/')
            p++;
        size_t len = p - begin;
        if (len > 255)
            return -36;
        char name[256];
        memcpy(name, pending + begin, len);
        name[len] = 0;
        if (!strcmp(name, "."))
            continue;
        if (!strcmp(name, "..")) {
            node = directory_parent(node);
            continue;
        }
        Node* child = nullptr;
        int error = node->mount->ops->lookup(node, name, child);
        if (error)
            return error;
        if (auto mount = mounted_on(child))
            child = mount->root;
        if ((child->mode & 0170000) == symlink && (follow || pending[p])) {
            if (++links > 40)
                return -40;
            auto target = file_node(child);
            if (!target->size)
                return -2;
            size_t tail = strlen(pending + p);
            if (target->size + tail >= sizeof(pending))
                return -36;
            char link[2048];
            int64_t count = node_read(target, 0, link, target->size);
            if (count < 0)
                return count;
            if (size_t(count) != target->size)
                return -5;
            memcpy(link + count, pending + p, tail + 1);
            memcpy(pending, link, size_t(count) + tail + 1);
            if (pending[0] == '/')
                node = root_node;
            p = 0;
            continue;
        }
        node = child;
    }
    result = node;
    return 0;
}
Node* lookup(const Path& path, bool follow) {
    Node* node = nullptr;
    resolve_path(path, node, follow);
    return node;
}
Node* lookup(const char* text, bool follow, unsigned) {
    Path path;
    path.base = root_node;
    if (!text || strlen(text) >= sizeof(path.text))
        return nullptr;
    memcpy(path.text, text, strlen(text) + 1);
    return lookup(path, follow);
}
static int parent_path(const Path& path, Node*& parent, char* name) {
    size_t length = strlen(path.text);
    while (length > 1 && path.text[length - 1] == '/')
        length--;
    size_t split = length;
    while (split && path.text[split - 1] != '/')
        split--;
    size_t len = length - split;
    if (!len)
        return -16;
    if (len > 255)
        return -36;
    memcpy(name, path.text + split, len);
    name[len] = 0;
    if (!strcmp(name, ".") || !strcmp(name, ".."))
        return -22;
    Path base;
    base.base = path.base;
    if (!split)
        memcpy(base.text, ".", 2);
    else {
        memcpy(base.text, path.text, split);
        base.text[split] = 0;
    }
    int error = resolve_path(base, parent);
    return error ? error : (parent->mode & 0170000) == directory ? 0 : -20;
}
bool node_readonly(Node* node) {
    return node && node->mount->readonly;
}
int create_node(const Path& path, uint32_t mode, Node*& node, const char* target) {
    Node* existing = nullptr;
    int error = resolve_path(path, existing, false);
    if (!error)
        return -17;
    if (error != -2)
        return error;
    Node* parent = nullptr;
    char name[256];
    error = parent_path(path, parent, name);
    if (error)
        return error;
    if (parent->removed)
        return -2;
    if (node_readonly(parent))
        return -30;
    error = parent->mount->ops->lookup(parent, name, existing);
    if (!error)
        return -17;
    if (error != -2)
        return error;
    size_t len = strlen(path.text);
    if ((mode & 0170000) != directory && len && path.text[len - 1] == '/')
        return -21;
    return parent->mount->ops->create(parent, name, mode, target, node);
}
Node* make_node(const char* text, uint32_t mode) {
    if (!strcmp(text, "/"))
        return root_node;
    Path path;
    path.base = root_node;
    if (strlen(text) >= sizeof(path.text))
        return nullptr;
    memcpy(path.text, text, strlen(text) + 1);
    Node* node = nullptr;
    return create_node(path, mode, node) ? nullptr : node;
}
int link_node(const Path& from, const Path& to, bool follow) {
    Node* target = nullptr;
    int error = resolve_path(from, target, follow);
    if (error)
        return error;
    target = file_node(target);
    if (to.text[strlen(to.text) - 1] == '/')
        return -2;
    if ((target->mode & 0170000) == directory)
        return -1;
    Node* parent = nullptr;
    char name[256];
    error = parent_path(to, parent, name);
    if (error)
        return error;
    if (target->mount != parent->mount)
        return -18;
    if (node_readonly(parent))
        return -30;
    Node* existing = nullptr;
    error = parent->mount->ops->lookup(parent, name, existing);
    if (!error)
        return -17;
    if (error != -2)
        return error;
    if ((target->mode & 0170000) != regular_file && (target->mode & 0170000) != symlink)
        return -95;
    return parent->mount->ops->link(target, parent, name);
}
static bool mount_root(Node* node) {
    return node == node->mount->root;
}
static int empty_directory(Node* node) {
    DirectoryEntry entry;
    uint64_t cookie = 0;
    while (true) {
        int result = node_readdir(node, cookie, entry);
        if (result <= 0)
            return result;
        if (strcmp(entry.name, ".") && strcmp(entry.name, ".."))
            return -39;
        if (entry.next == cookie)
            return -5;
        cookie = entry.next;
    }
}
static bool dot_component(const Path& path) {
    size_t end = strlen(path.text);
    while (end && path.text[end - 1] == '/')
        end--;
    size_t begin = end;
    while (begin && path.text[begin - 1] != '/')
        begin--;
    return (end - begin == 1 && path.text[begin] == '.') ||
           (end - begin == 2 && path.text[begin] == '.' && path.text[begin + 1] == '.');
}
int remove_node(const Path& path, bool dir) {
    if (dir && dot_component(path))
        return -22;
    Node* node = nullptr;
    int error = resolve_path(path, node, false);
    if (error)
        return error;
    if (mount_root(node) || mounted_on(node))
        return -16;
    if (node_readonly(node))
        return -30;
    if (dir) {
        if ((node->mode & 0170000) != directory)
            return -20;
        error = empty_directory(node);
        if (error)
            return error;
    } else if ((node->mode & 0170000) == directory)
        return -21;
    return node->mount->ops->remove(node);
}
int rename_node(const Path& from, const Path& to) {
    if (dot_component(from) || dot_component(to))
        return -16;
    Node* node = nullptr;
    int error = resolve_path(from, node, false);
    if (error)
        return error;
    Node* parent = nullptr;
    char name[256];
    error = parent_path(to, parent, name);
    if (error)
        return error;
    if (node->mount != parent->mount)
        return -18;
    if (mount_root(node) || mounted_on(node))
        return -16;
    if (node_readonly(node))
        return -30;
    Node* replaced = nullptr;
    error = parent->mount->ops->lookup(parent, name, replaced);
    if (error && error != -2)
        return error;
    if (to.text[strlen(to.text) - 1] == '/' && !replaced)
        return -2;
    if (replaced && (mount_root(replaced) || mounted_on(replaced)))
        return -16;
    if (replaced && file_node(replaced) == file_node(node))
        return 0;
    bool dir = (node->mode & 0170000) == directory;
    for (Node* n = parent; dir && n; n = n->parent)
        if (n == node)
            return -22;
    if (replaced) {
        bool other_dir = (replaced->mode & 0170000) == directory;
        if (dir != other_dir)
            return dir ? -20 : -21;
        if (other_dir && (error = empty_directory(replaced)))
            return error;
    }
    return node->mount->ops->rename(node, parent, name, replaced);
}
int node_truncate(Node* node, uint64_t size) {
    node = file_node(node);
    if (int64_t(size) < 0)
        return -22;
    if (!node || (node->mode & 0170000) != regular_file)
        return node && (node->mode & 0170000) == directory ? -21 : -22;
    if (node_readonly(node))
        return -30;
    return node->mount->ops->truncate(node, size);
}
bool node_resize(Node* node, size_t size) {
    return node_truncate(node, size) == 0;
}
int node_setattr(Node* node, uint32_t mode, Timestamp atime, Timestamp mtime) {
    node = file_node(node);
    if (node_readonly(node))
        return -30;
    return node->mount->ops->setattr(node, mode, atime, mtime);
}
int64_t node_read(Node* node, uint64_t offset, void* buffer, size_t length) {
    node = file_node(node);
    return node->mount->ops->read(node, offset, buffer, length);
}
int node_readdir(Node* node, uint64_t cookie, DirectoryEntry& entry) {
    return node->mount->ops->readdir(node, cookie, entry);
}
int node_sync(Node* node, bool data_only) {
    if (!node)
        return -22;
    if ((node->mode & 0170000) == block_device)
        return block_flush(node->device_id);
    return node->mount->ops->sync(node->mount, file_node(node), data_only);
}
int sync_filesystems() {
    int error = 0;
    for (auto& mount : mounts)
        if (mount.active) {
            int result = mount.ops->sync(&mount, nullptr, false);
            if (result && !error)
                error = result;
        }
    return error;
}
int node_map_shared(Node* node, uint64_t offset, size_t length, bool write, uint64_t& address) {
    if (write && node_readonly(node))
        return -30;
    if (!node->mount->ops->map_shared)
        return -19;
    return node->mount->ops->map_shared(node, offset, length, address);
}
FilesystemStats node_stats(Node* node) {
    return node->mount->ops->stats(node->mount);
}
static bool mount_busy(Mount* mount, bool writers_only) {
    if (!writers_only && socket_mount_busy(mount))
        return true;
    for (auto& h : handles)
        if (h.references && h.node && h.node->mount == mount &&
            (!writers_only || ((h.flags & 3) && (h.node->mode & 0170000) == regular_file)))
            return true;
    for (auto& task : tasks)
        if (!writers_only && task.state != State::empty && task.state != State::zombie &&
            task.cwd_node && task.cwd_node->mount == mount)
            return true;
    // Shared file pages outlive file descriptors, including after fork.
    for (size_t i = 0; i < node_count; i++) {
        auto& node = nodes[i];
        if (node.mount == mount && node.backing_physical &&
            page_shared(node.backing_physical, node.capacity / page_size))
            return true;
    }
    return false;
}
int mount_ramfs(const Path& path, const char* type, uint64_t flags) {
    if (flags & ~uint64_t(1 | 32))
        return -22;
    Node* point = nullptr;
    int error = resolve_path(path, point);
    if (error)
        return error;
    if ((point->mode & 0170000) != directory)
        return -20;
    if (flags & 32) {
        if (!mount_root(point))
            return -22;
        auto mount = point->mount;
        if ((flags & 1) && mount_busy(mount, true))
            return -16;
        error = mount->ops->sync(mount, nullptr, false);
        if (error)
            return error;
        mount->readonly = flags & 1;
        return 0;
    }
    if (!type || strcmp(type, "ramfs"))
        return -19;
    if (mount_root(point))
        return -16;
    for (auto& mount : mounts)
        if (!mount.active) {
            mount = {next_mount_id++, nullptr, point, point->mount, &ramfs_ops, nullptr,
                     false, bool(flags & 1)};
            mount.root = ramfs_root(&mount, 0755);
            if (!mount.root)
                return -28;
            mount.active = true;
            return 0;
        }
    return -28;
}
int unmount(const Path& path, uint64_t flags) {
    if (flags)
        return -22;
    Node* node = nullptr;
    int error = resolve_path(path, node);
    if (error)
        return error;
    if (!mount_root(node) || !node->mount->point)
        return -22;
    auto mount = node->mount;
    for (auto& child : mounts)
        if (child.active && child.parent == mount)
            return -16;
    if (mount_busy(mount, false))
        return -16;
    error = mount->ops->sync(mount, nullptr, false);
    if (error)
        return error;
    mount->active = false;
    mount->ops->destroy(mount);
    *mount = {};
    return 0;
}
static uint64_t hex(const char* p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) {
        char c = p[i];
        v = (v << 4) + (c <= '9' ? c - '0' : (c | 32) - 'a' + 10);
    }
    return v;
}
void vfs_init(const void* archive, size_t length) {
    mounts[0] = {next_mount_id++, nullptr, nullptr, nullptr, &ramfs_ops, nullptr, true, false};
    root_node = ramfs_root(&mounts[0], 0755);
    if (!root_node)
        panic("root allocation");
    mounts[0].root = root_node;
    auto data = (const uint8_t*)archive;
    size_t offset = 0;
    while (offset + 110 <= length) {
        auto h = (const char*)data + offset;
        if (memcmp(h, "070701", 6))
            panic("invalid newc initramfs");
        uint64_t mode = hex(h + 14), size = hex(h + 54), namesize = hex(h + 94);
        if (!namesize || namesize > 1024 || namesize > length - offset - 110)
            panic("invalid archive name");
        const char* name = h + 110;
        if (name[namesize - 1])
            panic("unterminated archive name");
        size_t content = (offset + 110 + namesize + 3) & ~size_t(3);
        if (content > length || size > length - content)
            panic("invalid archive size");
        if (!strcmp(name, "TRAILER!!!"))
            break;
        char path[1024];
        if (!normalize("/", name, path, sizeof(path)))
            panic("archive path too long");
        Node* n = lookup(path, false);
        if (!n)
            n = make_node(path, mode);
        if (!n)
            panic("invalid archive hierarchy");
        n->mode = mode;
        if ((mode & 0170000) == symlink) {
            n->data = (uint8_t*)alloc(size + 1);
            if (!n->data)
                panic("archive allocation");
            memcpy(n->data, data + content, size);
            n->data[size] = 0;
            n->owned = true;
            n->capacity = size + 1;
        } else
            n->data = const_cast<uint8_t*>(data + content);
        n->size = size;
        offset = (content + size + 3) & ~size_t(3);
    }
    const char* dirs[] = {"/dev", "/proc", "/tmp", "/run"};
    for (auto p : dirs)
        if (!lookup(p))
            make_node(p, directory | 0755);
    const char* devices[] = {"/dev/console", "/dev/tty",    "/dev/ttyS0",  "/dev/null",
                             "/dev/zero",    "/dev/random", "/dev/urandom"};
    for (auto p : devices)
        if (!lookup(p))
            make_node(p, character | 0666);
    log("VFS: imported %u nodes from initramfs\n", uint64_t(node_count));
}
Handle* open_handle(Node* n, uint32_t flags) {
    for (auto& h : handles)
        if (!h.references) {
            h = {file_node(n), nullptr, 0, flags, 1, false};
            h.generation = next_generation++;
            if (!device_open(&h)) {
                h.references = 0;
                return nullptr;
            }
            return &h;
        }
    return nullptr;
}
Handle* pipe_handle(Pipe* p, bool writer) {
    Handle* h = open_handle(nullptr, writer ? 1 : 0);
    if (h) {
        h->pipe = p;
        h->writer = writer;
        if (writer)
            p->writers++;
        else
            p->readers++;
    }
    return h;
}
void retain(Handle* h) {
    if (h)
        h->references++;
}
void close_handle(Handle* h) {
    if (!h || !h->references || --h->references)
        return;
    device_close(h);
    if (h->socket)
        socket_close(h->socket);
    if (h->epoll)
        epoll_close(h->epoll);
    if (h->pipe) {
        auto p = h->pipe;
        if (h->writer)
            p->writers--;
        else
            p->readers--;
        if (!p->readers && !p->writers)
            release(p);
    }
    h->node = nullptr;
    h->pipe = nullptr;
}
bool handle_ready(Handle* h, bool write) {
    if (!h)
        return true;
    if (h->socket)
        return socket_ready(h->socket, write);
    if (h->epoll)
        return true;
    if (h->pipe)
        return write ? h->pipe->size < sizeof(Pipe::bytes) || !h->pipe->readers
                     : h->pipe->size || !h->pipe->writers;
    if (!h->node || (h->node->mode & 0170000) != character)
        return true;
    return device_ready(h, write);
}
int64_t read_handle(Handle* h, void* buf, size_t len) {
    if ((h->flags & 3) == 1)
        return -9;
    if (!len)
        return 0;
    if (h->socket)
        return socket_read(h->socket, buf, len);
    auto data = (uint8_t*)buf;
    if (h->pipe) {
        auto p = h->pipe;
        if (!p->size)
            return p->writers ? -11 : 0;
        size_t n = min(len, p->size);
        for (size_t i = 0; i < n; i++) {
            data[i] = p->bytes[p->head];
            p->head = (p->head + 1) % sizeof(p->bytes);
        }
        p->size -= n;
        return n;
    }
    auto n = h->node;
    if (!n)
        return -9;
    if ((n->mode & 0170000) == directory)
        return -21;
    if ((n->mode & 0170000) == character || (n->mode & 0170000) == block_device)
        return device_read(h, buf, len);
    int64_t count = node_read(n, h->offset, buf, len);
    if (count > 0)
        h->offset += count;
    return count;
}
int64_t write_handle(Handle* h, const void* buf, size_t len) {
    if ((h->flags & 3) == 0)
        return -9;
    if (!len)
        return 0;
    if (h->socket)
        return socket_write(h->socket, buf, len);
    auto data = (const uint8_t*)buf;
    if (h->pipe) {
        auto p = h->pipe;
        if (!p->readers)
            return -32;
        if (p->size == sizeof(p->bytes))
            return -11;
        size_t n = min(len, sizeof(p->bytes) - p->size);
        for (size_t i = 0; i < n; i++)
            p->bytes[(p->head + p->size + i) % sizeof(p->bytes)] = data[i];
        p->size += n;
        return n;
    }
    auto n = h->node;
    if (!n)
        return -9;
    if ((n->mode & 0170000) == character || (n->mode & 0170000) == block_device)
        return device_write(h, buf, len);
    if ((n->mode & 0170000) != regular_file)
        return -21;
    if (h->flags & 02000)
        h->offset = n->size;
    if (node_readonly(n))
        return -30;
    int64_t count = n->mount->ops->write(n, h->offset, buf, len);
    if (count > 0) {
        h->offset += count;
        if (h->flags & 010000) {
            int error = node_sync(n, true);
            if (error)
                return error;
        }
    }
    return count;
}
} // namespace ax
