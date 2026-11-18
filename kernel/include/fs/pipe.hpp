// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "core/base.hpp"

namespace ax {
struct Handle;
struct Node;
struct Pipe;
struct Task;

void attach_pipe(Handle&, Pipe&);
void detach_pipe(Handle&);
int64_t open_fifo(Task&, Node* inode, Node* dentry, uint32_t flags);
bool resume_fifo_open(Task&);
void discard_fifo_open(Task&);
} // namespace ax
