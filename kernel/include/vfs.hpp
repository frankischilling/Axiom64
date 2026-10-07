// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "base.hpp"

namespace ax {
enum class Device;
struct Pty;
struct Socket;
struct Epoll;
struct Mount;
struct Timestamp {
    int64_t sec;
    uint64_t nsec;
};
Timestamp node_now();
constexpr uint32_t regular_file = 0100000, directory = 0040000, symlink = 0120000,
                   character = 0020000, block_device = 0060000;
struct Node {
    uint64_t inode;
    Node* parent;
    Node* first_child;
    Node* next_sibling;
    Node* hardlink;
    uint64_t links;
    uint64_t allocated_blocks;
    uint32_t uid, gid;
    char name[256];
    uint32_t mode;
    uint8_t* data;
    size_t size, capacity;
    uint64_t backing_physical;
    bool owned, removed;
    Device device;
    unsigned device_id;
    Timestamp atime, mtime, ctime;
    Mount* mount;
    void* filesystem_data;
};
// Relative paths retain their directory identity even when a mount covers it.
struct Path {
    Node* base = nullptr;
    char text[1024]{};
    int error = -14;
};
struct DirectoryEntry {
    uint64_t inode, next;
    uint32_t mode;
    char name[256];
};
struct FilesystemStats {
    uint64_t type, block_size, blocks, free_blocks, files, free_files;
};
// Methods return Linux negative errors; read/write return a byte count on success.
// VFS checks mount policy and namespace constraints before calling an adapter.
struct FilesystemOps {
    int (*lookup)(Node*, const char*, Node*&);
    int (*create)(Node*, const char*, uint32_t, const char*, Node*&);
    int (*link)(Node*, Node*, const char*);
    int (*remove)(Node*);
    int (*rename)(Node*, Node*, const char*, Node*);
    int64_t (*read)(Node*, uint64_t, void*, size_t);
    int64_t (*write)(Node*, uint64_t, const void*, size_t);
    int (*truncate)(Node*, size_t);
    int (*setattr)(Node*, uint32_t, Timestamp, Timestamp);
    int (*readdir)(Node*, uint64_t, DirectoryEntry&);
    int (*sync)(Mount*, Node*, bool);
    int (*map_shared)(Node*, uint64_t, size_t, uint64_t&);
    int (*stats)(Mount*, FilesystemStats&);
    void (*destroy)(Mount*);
    int (*remount)(Mount*, bool);
    int (*prepare_unmount)(Mount*);
};
struct Mount {
    uint64_t id;
    Node* root;
    Node* point;
    Mount* parent;
    const FilesystemOps* ops;
    void* data;
    bool active, readonly;
};
extern const FilesystemOps ramfs_ops;
Node* ramfs_root(Mount*, uint32_t);
struct Pipe {
    uint8_t bytes[16384];
    size_t head, size;
    unsigned readers, writers;
};
struct Handle {
    Node* node;
    Pipe* pipe;
    uint64_t offset;
    uint32_t flags;
    unsigned references;
    bool writer;
    Pty* pty = nullptr;
    Socket* socket = nullptr;
    Epoll* epoll = nullptr;
    uint64_t generation = 0;
};
extern Node* root_node;
extern Node nodes[16384];
extern size_t node_count;
void vfs_init(const void*, size_t);
bool normalize(const char* cwd, const char* path, char* result, size_t capacity);
Node* lookup(const char*, bool follow = true, unsigned depth = 0);
Node* lookup(const Path&, bool follow = true);
int resolve_path(const Path&, Node*&, bool follow = true);
Node* make_node(const char*, uint32_t);
int create_node(const Path&, uint32_t, Node*&, const char* target = nullptr);
int link_node(const Path&, const Path&, bool follow);
int remove_node(const Path&, bool directory);
int rename_node(const Path&, const Path&);
int mount_filesystem(const Path&, const Path&, const char*, uint64_t);
int unmount(const Path&, uint64_t);
Node* directory_parent(Node*);
bool node_readonly(Node*);
inline Node* file_node(Node* node) {
    return node && node->hardlink ? node->hardlink : node;
}
bool node_resize(Node*, size_t);
int node_truncate(Node*, uint64_t);
int node_setattr(Node*, uint32_t, Timestamp, Timestamp);
int64_t node_read(Node*, uint64_t, void*, size_t);
int node_readdir(Node*, uint64_t, DirectoryEntry&);
int node_sync(Node*, bool data_only = false);
int sync_filesystems();
int node_map_shared(Node*, uint64_t, size_t, bool write, uint64_t&);
int node_stats(Node*, FilesystemStats&);
bool node_referenced(Node*);
Handle* open_handle(Node*, uint32_t);
Handle* pipe_handle(Pipe*, bool);
void retain(Handle*);
void close_handle(Handle*);
int64_t read_handle(Handle*, void*, size_t);
int64_t write_handle(Handle*, const void*, size_t);
bool handle_ready(Handle*, bool write);
void node_path(Node*, char*, size_t);
} // namespace ax
