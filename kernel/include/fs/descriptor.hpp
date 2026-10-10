// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

namespace ax {
struct FileTable;
struct Handle;

// A reservation owns a table slot without exposing a file. Install exactly once,
// or discard on failure/interruption. The owning task keeps the table alive.
int reserve_fd(FileTable&, int start = 0, bool cloexec = false);
void install_reserved_fd(FileTable&, int, Handle*);
void discard_reserved_fd(FileTable&, int);
} // namespace ax
