// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "fs/vfs.hpp"

namespace ax {
extern const FilesystemOps procfs_ops;
Node* procfs_root(Mount*);
bool procfs_has_poll(const Node&);
} // namespace ax
