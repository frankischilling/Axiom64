// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "fs/inotify_queue.hpp"

namespace ax {
struct Handle;
struct Mount;
struct Node;

constexpr uint32_t inotify_access = 0x00000001;
constexpr uint32_t inotify_modify = 0x00000002;
constexpr uint32_t inotify_attrib = 0x00000004;
constexpr uint32_t inotify_close_write = 0x00000008;
constexpr uint32_t inotify_close_nowrite = 0x00000010;
constexpr uint32_t inotify_open = 0x00000020;
constexpr uint32_t inotify_moved_from = 0x00000040;
constexpr uint32_t inotify_moved_to = 0x00000080;
constexpr uint32_t inotify_create = 0x00000100;
constexpr uint32_t inotify_delete = 0x00000200;
constexpr uint32_t inotify_delete_self = 0x00000400;
constexpr uint32_t inotify_move_self = 0x00000800;
constexpr uint32_t inotify_unmount = 0x00002000;
constexpr uint32_t inotify_onlydir = 0x01000000;
constexpr uint32_t inotify_dont_follow = 0x02000000;
constexpr uint32_t inotify_excl_unlink = 0x04000000;
constexpr uint32_t inotify_mask_create = 0x10000000;
constexpr uint32_t inotify_mask_add = 0x20000000;
constexpr uint32_t inotify_isdir = 0x40000000;
constexpr uint32_t inotify_oneshot = 0x80000000;
constexpr uint32_t inotify_events = 0x00000fff;
constexpr uint32_t inotify_read_events = 0x41; // POLLIN | POLLRDNORM
constexpr uint32_t inotify_flags = inotify_onlydir | inotify_dont_follow | inotify_excl_unlink |
                                   inotify_mask_create | inotify_mask_add | inotify_isdir |
                                   inotify_oneshot;

struct Inotify;
Handle* open_inotify(uint32_t uid, bool nonblocking, int& error);
void close_inotify(Inotify*);
int inotify_add_watch(Inotify&, Node*, uint32_t mask);
int inotify_remove_watch(Inotify&, int wd);
InotifyQueue& inotify_queue(Inotify&);

void inotify_inode(Node*, uint32_t mask);
void inotify_dentry(Node*, uint32_t mask);
void inotify_name(Node* parent, uint32_t mask, const char* name, uint32_t cookie = 0);
uint32_t inotify_move_cookie();
void inotify_retire_inode(Node*);
void inotify_reap_inodes();
void inotify_retire_mount(const Mount&);
} // namespace ax
