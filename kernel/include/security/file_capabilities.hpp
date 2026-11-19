// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/security/file_capabilities.hpp
 * @brief   File capability interface.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Declares parsing and application of file capabilities when executing a
 * program.
 *
 * Copyright (C) 2026 frankischilling
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://gnu.org/licenses/>.
 */
#pragma once
#include <cstddef>
#include <cstdint>

namespace ax {
// A nonzero root ID describes a namespace which this kernel does not implement.
// Keep its metadata, but it cannot grant capabilities to the initial namespace.
struct FileCapabilities {
    uint64_t permitted = 0, inheritable = 0;
    uint32_t root_id = 0;
    bool present = false, effective = false;
};

enum class FileCapabilityUse { execute, read, write };

// Stored revision 1 is readable by exec; Linux rejects new revision-1 writes.
// The public read path converts a root-zero revision 3 to revision 2.
// Write callers check root-ID applicability after the administration permission.
int file_capabilities_decode(const void*, size_t, FileCapabilities&,
                             FileCapabilityUse = FileCapabilityUse::execute);
int64_t file_capabilities_export(const void*, size_t, void*, size_t);
} // namespace ax
