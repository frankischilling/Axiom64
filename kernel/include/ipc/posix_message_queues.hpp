// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "process/task.hpp"

namespace ax {
const FilesystemOps& posix_queue_filesystem();
void posix_queue_mount(Node*);
bool posix_queue_mounted();
bool posix_queue_ready(const Node*, bool write);
void posix_queue_reap(Node*);
void posix_queue_descriptor_closed(Handle*);
void posix_queue_process_exit(const Process&);
void posix_queue_discard(Task&);
void posix_queue_resume(Task&);
bool posix_queue_expire(Task&);
int64_t posix_queue_syscall(Frame*);
} // namespace ax
