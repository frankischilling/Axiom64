// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

namespace ax {
struct FileTable;
struct Handle;
struct Task;

// A reservation owns a table slot without exposing a file. Install exactly once,
// or discard on failure/interruption. The owning task keeps the table alive.
int reserve_fd(Task&, int start = 0, bool cloexec = false);
void install_reserved_fd(FileTable&, int, Handle*);
void discard_reserved_fd(FileTable&, int);
// Closing or replacing a visible descriptor releases that table's POSIX locks
// on the inode, independently of description references retained elsewhere.
void close_descriptor(FileTable&, int);
} // namespace ax
