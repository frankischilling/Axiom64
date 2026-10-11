// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "fs/xattr.hpp"

namespace ax {
bool ext2_xattr_valid(const void*, size_t, uint32_t& references);
bool ext2_xattr_supported(const void*, size_t);
int64_t ext2_xattr_get(const void*, size_t, const XattrName&, void*, size_t);
int64_t ext2_xattr_list(const void*, size_t, void*, size_t, bool trusted);
// Build a complete private replacement block before the filesystem stages it.
// The source and destination must be distinct; a null source means no attributes.
int ext2_xattr_change(const void*, size_t, const XattrName&, const void*, size_t, unsigned flags,
                      bool remove, void*, bool& empty);
} // namespace ax
