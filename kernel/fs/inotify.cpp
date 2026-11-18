// SPDX-License-Identifier: GPL-3.0-or-later
#include "fs/inotify.hpp"
#include "fs/vfs.hpp"
#include "ipc/ipc.hpp"

namespace ax {
namespace {
constexpr unsigned instances_per_user = 128;
constexpr unsigned watches_per_user = 8192;
constexpr unsigned bucket_count = 1024;

struct WatchBlock;

struct Watch {
    Inotify* owner;
    WatchBlock* block;
    Watch* next_inode;
    Watch** previous_inode;
    Watch* next_pending;
    Watch** previous_pending;
    Node* pending_node;
    uint64_t mount;
    uint64_t inode;
    int wd;
    uint32_t mask;
    bool is_directory;
};

struct WatchBlock {
    WatchBlock* next;
    WatchBlock** previous;
    unsigned used;
    Watch watches[46];
};

static_assert(sizeof(WatchBlock) + 16 <= page_size);
Watch* by_inode[bucket_count];
Watch* pending_inodes;
Inotify* instances;
uint32_t move_cookie;

Watch*& inode_bucket(uint64_t mount, uint64_t inode) {
    uint64_t value = (mount << 5) ^ inode ^ (inode >> 10);
    return by_inode[value % bucket_count];
}
} // namespace

struct Inotify {
    Inotify* next;
    WatchBlock* blocks;
    Handle* handle;
    InotifyQueue queue;
    uint32_t uid;
    int last_wd;
    unsigned watches;
    bool wrapped;
};

Handle* open_inotify(uint32_t uid, bool nonblocking, int& error) {
    unsigned count = 0;
    for (auto instance = instances; instance; instance = instance->next)
        count += instance->uid == uid;
    error = -24;
    if (count >= instances_per_user)
        return nullptr;
    auto instance = static_cast<Inotify*>(alloc(sizeof(Inotify)));
    error = -12;
    if (!instance)
        return nullptr;
    auto handle = open_handle(nullptr, nonblocking ? 04000 : 0, &error);
    if (!handle) {
        release(instance);
        return nullptr;
    }
    *instance = {};
    instance->handle = handle;
    instance->uid = uid;
    instance->next = instances;
    instances = instance;
    handle->inotify = instance;
    return handle;
}

static void unlink_watch(Watch& watch) {
    *watch.previous_inode = watch.next_inode;
    if (watch.next_inode)
        watch.next_inode->previous_inode = watch.previous_inode;
    if (watch.previous_pending) {
        *watch.previous_pending = watch.next_pending;
        if (watch.next_pending)
            watch.next_pending->previous_pending = watch.previous_pending;
    }
    --watch.owner->watches;
    auto block = watch.block;
    watch = {};
    if (!--block->used) {
        *block->previous = block->next;
        if (block->next)
            block->next->previous = block->previous;
        release(block);
    }
}

static void enqueue(Watch& watch, uint32_t mask, uint32_t cookie, const char* name) {
    auto& instance = *watch.owner;
    size_t before = instance.queue.bytes();
    instance.queue.push(watch.wd, mask, cookie, name);
    if (instance.queue.bytes() != before)
        epoll_notify(instance.handle, inotify_read_events);
}

static void retire_watch(Watch& watch) {
    enqueue(watch, inotify_watch_ignored, 0, nullptr);
    unlink_watch(watch);
}

void close_inotify(Inotify* instance) {
    auto link = &instances;
    while (*link != instance)
        link = &(*link)->next;
    *link = instance->next;
    while (instance->blocks) {
        auto block = instance->blocks;
        // The last watch releases the block.
        for (auto& watch : block->watches) {
            if (!watch.owner)
                continue;
            bool last = block->used == 1;
            unlink_watch(watch);
            if (last)
                break;
        }
    }
    instance->queue.clear();
    release(instance);
}

static Watch* watch_number(Inotify& instance, int wd) {
    if (wd <= 0)
        return nullptr;
    for (auto block = instance.blocks; block; block = block->next)
        for (auto& watch : block->watches)
            if (watch.wd == wd)
                return &watch;
    return nullptr;
}

static WatchBlock* admit_watch(Inotify& instance, int& error) {
    unsigned count = 0;
    for (auto other = instances; other; other = other->next)
        if (other->uid == instance.uid)
            count += other->watches;
    if (count >= watches_per_user) {
        error = -28;
        return nullptr;
    }
    for (auto block = instance.blocks; block; block = block->next)
        if (block->used < sizeof(block->watches) / sizeof(Watch))
            return block;
    auto block = static_cast<WatchBlock*>(alloc(sizeof(WatchBlock)));
    if (!block) {
        error = -12;
        return nullptr;
    }
    *block = {};
    block->previous = &instance.blocks;
    block->next = instance.blocks;
    if (block->next)
        block->next->previous = &block->next;
    instance.blocks = block;
    return block;
}

int inotify_add_watch(Inotify& instance, Node* node, uint32_t mask) {
    node = file_node(node);
    uint64_t mount = node->mount->id;
    uint64_t inode = node->inode;
    auto& bucket = inode_bucket(mount, inode);
    uint32_t wanted =
        (mask & (inotify_events | inotify_excl_unlink | inotify_oneshot)) | inotify_unmount;
    for (auto watch = bucket; watch; watch = watch->next_inode) {
        if (watch->owner != &instance || watch->mount != mount || watch->inode != inode)
            continue;
        if (mask & inotify_mask_create)
            return -17;
        watch->mask = wanted | ((mask & inotify_mask_add) ? watch->mask : 0);
        return watch->wd;
    }
    int error;
    auto block = admit_watch(instance, error);
    if (!block)
        return error;
    int wd = instance.last_wd;
    do {
        if (wd == INT32_MAX) {
            wd = 0;
            instance.wrapped = true;
        }
        ++wd;
    } while (instance.wrapped && watch_number(instance, wd));
    auto watch = block->watches;
    while (watch->owner)
        ++watch;
    *watch = {
        .owner = &instance,
        .block = block,
        .next_inode = bucket,
        .previous_inode = &bucket,
        .next_pending = nullptr,
        .previous_pending = nullptr,
        .pending_node = nullptr,
        .mount = mount,
        .inode = inode,
        .wd = wd,
        .mask = wanted,
        .is_directory = (node->mode & 0170000) == directory,
    };
    if (bucket)
        bucket->previous_inode = &watch->next_inode;
    bucket = watch;
    ++block->used;
    ++instance.watches;
    instance.last_wd = wd;
    return wd;
}

int inotify_remove_watch(Inotify& instance, int wd) {
    auto watch = watch_number(instance, wd);
    if (!watch)
        return -22;
    retire_watch(*watch);
    return 0;
}

InotifyQueue& inotify_queue(Inotify& instance) {
    return instance.queue;
}

static void report(Node* node, uint32_t mask, const char* name, uint32_t cookie, bool detached,
                   bool retire) {
    if (!node || !instances)
        return;
    node = file_node(node);
    uint64_t mount = node->mount->id;
    uint64_t inode = node->inode;
    for (auto watch = inode_bucket(mount, inode); watch;) {
        auto next = watch->next_inode;
        if (watch->mount == mount && watch->inode == inode) {
            bool deliver = (watch->mask & mask & ~inotify_isdir) &&
                           !(detached && (watch->mask & inotify_excl_unlink));
            if (deliver)
                enqueue(*watch, mask, cookie, name);
            if (retire || (deliver && (watch->mask & inotify_oneshot)))
                retire_watch(*watch);
        }
        watch = next;
    }
}

void inotify_inode(Node* node, uint32_t mask) {
    report(node, mask, nullptr, 0, false, false);
}

void inotify_dentry(Node* node, uint32_t mask) {
    if (!node || !instances)
        return;
    if ((node->mode & 0170000) == directory)
        mask |= inotify_isdir;
    report(node->parent, mask, node->name, 0, node->removed, false);
    report(node, mask, nullptr, 0, node->removed, false);
}

void inotify_name(Node* parent, uint32_t mask, const char* name, uint32_t cookie) {
    report(parent, mask, name, cookie, false, false);
}

uint32_t inotify_move_cookie() {
    if (!++move_cookie)
        ++move_cookie;
    return move_cookie;
}

void inotify_retire_inode(Node* node) {
    if (!node || !instances)
        return;
    node = file_node(node);
    if (node->links || !node->mount)
        return;
    uint64_t mount = node->mount->id;
    auto bucket = inode_bucket(mount, node->inode);
    for (auto watch = bucket; watch; watch = watch->next_inode) {
        if (watch->mount == mount && watch->inode == node->inode) {
            if (!node_referenced(node)) {
                report(node, inotify_delete_self, nullptr, 0, false, true);
            } else {
                for (auto entry = watch; entry; entry = entry->next_inode) {
                    if (entry->mount != mount || entry->inode != node->inode || entry->pending_node)
                        continue;
                    entry->pending_node = node;
                    entry->next_pending = pending_inodes;
                    entry->previous_pending = &pending_inodes;
                    if (pending_inodes)
                        pending_inodes->previous_pending = &entry->next_pending;
                    pending_inodes = entry;
                }
            }
            return;
        }
    }
}

void inotify_reap_inodes() {
    for (auto watch = pending_inodes; watch;) {
        auto next = watch->next_pending;
        if (!node_referenced(watch->pending_node)) {
            if (watch->mask & inotify_delete_self)
                enqueue(*watch, inotify_delete_self, 0, nullptr);
            retire_watch(*watch);
        }
        watch = next;
    }
}

void inotify_retire_mount(const Mount& mount) {
    if (!instances)
        return;
    for (auto bucket : by_inode)
        for (auto watch = bucket; watch;) {
            auto next = watch->next_inode;
            if (watch->mount == mount.id) {
                uint32_t mask = inotify_unmount | (watch->is_directory ? inotify_isdir : 0);
                enqueue(*watch, mask, 0, nullptr);
                retire_watch(*watch);
            }
            watch = next;
        }
}
} // namespace ax
