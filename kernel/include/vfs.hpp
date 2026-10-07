// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "base.hpp"

namespace ax {
enum class Device;
struct Pty;
struct Socket;
struct Epoll;
struct Timestamp {
    int64_t sec;
    uint64_t nsec;
};
Timestamp node_now();
constexpr uint32_t regular_file = 0100000, directory = 0040000, symlink = 0120000,
                   character = 0020000;
struct Node {
    uint64_t inode;
    Node* parent;
    Node* first_child;
    Node* next_sibling;
    Node* hardlink;
    uint64_t links;
    char name[128];
    uint32_t mode;
    uint8_t* data;
    size_t size, capacity;
    uint64_t backing_physical;
    bool owned, removed;
    Device device;
    unsigned device_id;
    Timestamp atime, mtime, ctime;
};
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
Node* make_node(const char*, uint32_t);
inline Node* file_node(Node* node) {
    return node && node->hardlink ? node->hardlink : node;
}
bool node_resize(Node*, size_t);
Handle* open_handle(Node*, uint32_t);
Handle* pipe_handle(Pipe*, bool);
void retain(Handle*);
void close_handle(Handle*);
int64_t read_handle(Handle*, void*, size_t);
int64_t write_handle(Handle*, const void*, size_t);
bool handle_ready(Handle*, bool write);
void node_path(Node*, char*, size_t);
} // namespace ax
