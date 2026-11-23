// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/fs/vfs.hpp
 * @brief   Virtual filesystem types and operations.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Defines nodes, mounts, path walking, filesystem operations, and
 * open-description interfaces.
 *
 * Copyright (C) 2026 frankischilling
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://gnu.org/licenses/>.
 */
#pragma once
#include "core/base.hpp"

namespace ax {
constexpr unsigned max_handles = 8192;
enum class Device;
struct Pty;
struct Socket;
struct PacketSocket;
struct InetSocket;
struct Inet6Socket;
struct NetlinkSocket;
struct Epoll;
struct Eventfd;
struct Timerfd;
struct SignalDescriptor;
struct Task;
struct Inotify;
struct Mount;
struct Handle;
struct Pipe;
struct Xattr;
struct XattrName;

struct Timestamp {
    int64_t sec;
    uint64_t nsec;
};

Timestamp node_now();

constexpr uint32_t regular_file = 0100000, directory = 0040000, symlink = 0120000,
                   character = 0020000, block_device = 0060000, fifo = 0010000;

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
    bool owned, removed;
    uint8_t* data;
    size_t size, capacity;
    uint64_t backing_physical;
    Device device;
    unsigned device_id;
    Timestamp atime, mtime, ctime;
    Mount* mount;
    void* filesystem_data;
    Xattr* xattrs = nullptr;
    unsigned lock_readers, exec_images;
    Handle* lock_writer;
    Pipe* named_pipe = nullptr;
    FileMapping* disk_mappings = nullptr;
};

// Relative paths retain their directory identity even when a mount covers it.
struct Path {
    Node* base = nullptr;
    char text[1024]{};
    int error = -14;
    bool real_access = false;
};

struct DirectoryEntry {
    uint64_t inode, next;
    uint32_t mode;
    char name[256];
};

struct FilesystemStats {
    uint64_t type, block_size, blocks, free_blocks, files, free_files;
};

// Control files consume a complete I/O operation and own their description's
// position. Ordinary files and sequential proc snapshots keep the usual path.
struct ControlFileOps {
    int (*access)(Node*, unsigned mask, bool real);
    int64_t (*read)(Handle*, void*, size_t);
    int64_t (*write)(Handle*, const void*, size_t);
    int (*truncate)(Node*, size_t);
    uint32_t (*poll_events)(const Handle&) = nullptr;
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
    int (*setattr)(Node*, uint32_t, Timestamp, Timestamp, uint32_t, uint32_t);
    int (*readdir)(Node*, uint64_t, DirectoryEntry&);
    int (*sync)(Mount*, Node*, bool);
    int (*map_shared)(Node*, uint64_t, size_t, uint64_t&);
    int (*stats)(Mount*, FilesystemStats&);
    void (*destroy)(Mount*);
    int (*remount)(Mount*, bool);
    int (*prepare_unmount)(Mount*);
    int64_t (*getxattr)(Node*, const XattrName&, void*, size_t) = nullptr;
    int64_t (*listxattr)(Node*, void*, size_t, bool trusted) = nullptr;
    int (*setxattr)(Node*, const XattrName&, const void*, size_t, unsigned) = nullptr;
    int (*removexattr)(Node*, const XattrName&) = nullptr;
    // Dynamic metadata and description-owned sequential-read snapshots.
    void (*refresh)(Node*) = nullptr;
    int64_t (*read_description)(Handle*, uint64_t, void*, size_t) = nullptr;
    void (*close_description)(Handle*) = nullptr;
    const ControlFileOps* (*control)(Node*) = nullptr;
    // Dynamic filesystem objects may retire while descriptions still pin them.
    int (*validate)(Node*) = nullptr;
    // Positive results supply the resolved node of a filesystem-specific link.
    int (*follow_link)(Node*, Node*&) = nullptr;
    // Positive grants access, negative denies it, and zero applies ordinary DAC.
    int (*access_override)(Node*, unsigned mask) = nullptr;
    bool (*queue_reclaim)(Node*) = nullptr;
    void (*reclaim_queued)(Mount*) = nullptr;
    // A directory can contain kernel-owned control files that do not block rmdir.
    int (*directory_empty)(Node*) = nullptr;
};

struct Mount {
    uint64_t id;
    Node* root;
    Node* point;
    Mount* parent;
    const FilesystemOps* ops;
    void* data;
    bool active, readonly;
    bool nosuid = false, nodev = false, noexec = false;
};

inline constexpr unsigned mount_table_limit = 16;

extern const FilesystemOps ramfs_ops;

Node* ramfs_root(Mount*, uint32_t);

// Release an unlinked, unreferenced kernel-created character device.
void ramfs_reclaim_device(Node*);
bool ramfs_reclaim_unlinked(Node*);

struct SocketTimeout {
    uint64_t ticks = 0;
    bool finite = false;
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
    PacketSocket* packet = nullptr;
    InetSocket* inet = nullptr;
    Inet6Socket* inet6 = nullptr;
    NetlinkSocket* netlink = nullptr;
    Epoll* epoll = nullptr;
    Eventfd* event = nullptr;
    Timerfd* timer = nullptr;
    SignalDescriptor* signal_descriptor = nullptr;
    Inotify* inotify = nullptr;
    Node* opened_dentry = nullptr;
    uint64_t generation = 0;
    uint8_t file_lock = 0;
    void* filesystem_data = nullptr;
    SocketTimeout receive_timeout{}, send_timeout{};
    uint64_t pipe_hangup_generation = 0;
    Node* anonymous_path = nullptr;
    uint32_t opener_uid = 0, opener_gid = 0;
    Handle* next_free = nullptr;
};

inline uint32_t file_status_flags(const Handle& handle) {
    return handle.flags & ~uint32_t(02000000 | 0100 | 0200 | 0400 | 01000);
}

extern Node* root_node;
extern Node nodes[16384];
extern size_t node_count;

void vfs_init(const void*, size_t);

// Boot-only root replacement, before any task or file description exists.
int vfs_disk_root(unsigned device, bool readonly, bool check_dirty = false);

bool normalize(const char* cwd, const char* path, char* result, size_t capacity);

Node* lookup(const char*, bool follow = true, unsigned depth = 0);

Node* lookup(const Path&, bool follow = true);

int resolve_path(const Path&, Node*&, bool follow = true);

Node* make_node(const char*, uint32_t);

int create_node(const Path&, uint32_t, Node*&, const char* target = nullptr);

int link_node(const Path&, const Path&, bool follow);

int remove_node(const Path&, bool directory);

int rename_node(const Path&, const Path&, bool no_replace = false);

int mount_filesystem(const Path&, const Path&, const char*, uint64_t, bool check_dirty = false,
                     const char* options = nullptr);

int unmount(const Path&, uint64_t);

Node* directory_parent(Node*);

bool node_readonly(Node*);

inline Node* file_node(Node* node) {
    return node && node->hardlink ? node->hardlink : node;
}

bool node_resize(Node*, size_t);

int node_truncate(Node*, uint64_t);

int node_setattr(Node*, uint32_t, Timestamp, Timestamp, uint32_t event_mask = 0);
int node_access(Node*, unsigned mask, bool real = false);

const ControlFileOps* node_control(Node*);
void ramfs_set_control(Node*, const ControlFileOps*);
int node_validate(Node*);
int node_chmod(Node*, uint32_t);
int node_chown(Node*, uint32_t, uint32_t);

int64_t node_read(Node*, uint64_t, void*, size_t);
int64_t description_read(Handle*, uint64_t, void*, size_t);

int node_readdir(Node*, uint64_t, DirectoryEntry&);

int node_sync(Node*, bool data_only = false);

int sync_filesystems();

int shutdown_filesystems();

int node_map_shared(Node*, uint64_t, size_t, bool write, uint64_t&);

int node_stats(Node*, FilesystemStats&);

bool node_referenced(Node*);
void node_reference_released(Node*);
void schedule_filesystem_reclaim();
void reclaim_released_nodes();
bool node_open_for_write(const Node*);

Handle* open_handle(Node*, uint32_t, int* error = nullptr);

Handle* pipe_handle(Pipe*, bool);

void retain(Handle*);

void close_handle(Handle*);

int64_t read_handle(Handle*, void*, size_t);

// Clamp a complete regular-file write before inspecting user payload pages.
int write_handle_limit(Handle*, size_t&);
int write_handle_limit_at(Task*, Handle&, uint64_t, size_t&);

int64_t write_handle(Handle*, const void*, size_t);
// Callers clamp the transfer with write_handle_limit_at before committing bytes.
int prepare_regular_write(Task*, Node*);
int64_t write_regular_at(Task*, Handle&, uint64_t&, const void*, size_t);

bool handle_has_poll(const Handle&);
bool handle_ready(Handle*, bool write, const Task*);

void node_path(Node*, char*, size_t, bool include_unlinked = false, Node* boundary = nullptr);
const Mount* next_mount(unsigned& cursor);
} // namespace ax
