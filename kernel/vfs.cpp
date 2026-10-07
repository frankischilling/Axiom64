// SPDX-License-Identifier: GPL-3.0-or-later
#include "vfs.hpp"
#include "devices.hpp"
#include "ipc.hpp"

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
static Node* child(Node* parent, const char* name, size_t len) {
    for (Node* n = parent->first_child; n; n = n->next_sibling)
        if (!n->removed && strlen(n->name) == len && !memcmp(n->name, name, len))
            return n;
    return nullptr;
}
void node_path(Node* n, char* result, size_t cap) {
    if (n == root_node) {
        if (cap >= 2) {
            result[0] = '/';
            result[1] = 0;
        }
        return;
    }
    Node* chain[128];
    size_t count = 0;
    while (n && n != root_node && count < 128) {
        chain[count++] = n;
        n = n->parent;
    }
    size_t offset = 0;
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
Node* lookup(const char* path, bool follow, unsigned depth) {
    if (depth > 16 || !path || *path != '/')
        return nullptr;
    Node* n = root_node;
    for (size_t p = 0; path[p];) {
        while (path[p] == '/')
            p++;
        size_t begin = p;
        while (path[p] && path[p] != '/')
            p++;
        size_t len = p - begin;
        if (!len)
            break;
        if ((n->mode & 0170000) != directory)
            return nullptr;
        n = child(n, path + begin, len);
        if (!n)
            return nullptr;
        if ((n->mode & 0170000) == symlink && (follow || path[p])) {
            char base[1024], resolved[2048], combined[2048];
            node_path(n->parent, base, sizeof(base));
            if (!normalize(base, (const char*)n->data, resolved, sizeof(resolved)))
                return nullptr;
            size_t a = strlen(resolved), b = strlen(path + p);
            if (a + b >= sizeof(combined))
                return nullptr;
            memcpy(combined, resolved, a);
            memcpy(combined + a, path + p, b + 1);
            return lookup(combined, follow, depth + 1);
        }
    }
    return n;
}
Node* make_node(const char* path, uint32_t mode) {
    if (!strcmp(path, "/"))
        return root_node;
    if (node_count == sizeof(nodes) / sizeof(nodes[0]))
        return nullptr;
    size_t length = strlen(path), split = length;
    while (split && path[split - 1] != '/')
        split--;
    if (!split || length - split >= sizeof(Node::name))
        return nullptr;
    char parent_path[1024];
    size_t pn = split == 1 ? 1 : split - 1;
    if (pn >= sizeof(parent_path))
        return nullptr;
    memcpy(parent_path, path, pn);
    parent_path[pn] = 0;
    Node* parent = lookup(parent_path);
    if (!parent || (parent->mode & 0170000) != directory ||
        child(parent, path + split, length - split))
        return nullptr;
    Node* n = &nodes[node_count++];
    n->inode = node_count;
    n->links = 1;
    n->parent = parent;
    n->mode = mode;
    n->atime = n->mtime = n->ctime = node_now();
    n->next_sibling = parent->first_child;
    parent->first_child = n;
    memcpy(n->name, path + split, length - split + 1);
    return n;
}
bool node_resize(Node* n, size_t size) {
    n = file_node(n);
    if (size > 256 * 1024 * 1024)
        return false;
    if (!n->owned || size > n->capacity) {
        if (n->backing_physical && page_shared(n->backing_physical, n->capacity / page_size))
            return false;
        size_t cap = align_up(
            max(size, min(size_t(256 * 1024 * 1024), max(size_t(65536), n->capacity * 2))));
        uint64_t backing = page_alloc(cap / page_size);
        if (!backing)
            return false;
        auto data = (uint8_t*)physical(backing);
        memcpy(data, n->data, min(n->size, size));
        if (n->backing_physical)
            page_free(n->backing_physical, n->capacity / page_size);
        else if (n->owned)
            release(n->data);
        n->data = data;
        n->backing_physical = backing;
        n->owned = true;
        n->capacity = cap;
    }
    if (size > n->size)
        memset(n->data + n->size, 0, size - n->size);
    else if (size < n->size && n->owned)
        memset(n->data + size, 0, n->size - size);
    n->size = size;
    n->mtime = n->ctime = node_now();
    return true;
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
    root_node = &nodes[node_count++];
    root_node->mode = directory | 0755;
    root_node->inode = 1;
    root_node->links = 1;
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
    if (h->offset >= n->size)
        return 0;
    size_t count = min(len, n->size - size_t(h->offset));
    memcpy(buf, n->data + h->offset, count);
    h->offset += count;
    n->atime = node_now();
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
    if (h->offset > SIZE_MAX - len)
        return -27;
    if (h->offset + len > n->size || !n->owned)
        if (!node_resize(n, max(size_t(h->offset + len), n->size)))
            return -28;
    memcpy(n->data + h->offset, buf, len);
    h->offset += len;
    n->mtime = n->ctime = node_now();
    return len;
}
} // namespace ax
