// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "fs/vfs.hpp"

namespace ax {
extern const FilesystemOps ext2_ops;
int ext2_mount(Mount*, Node* device);
} // namespace ax
