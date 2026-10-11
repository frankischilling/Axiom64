// SPDX-License-Identifier: GPL-3.0-or-later
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
