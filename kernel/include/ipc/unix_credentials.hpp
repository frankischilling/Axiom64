// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <cstddef>
#include <cstdint>

namespace ax {
struct Task;

// A queued message keeps its captured identity after the sender exits. An
// uncaptured message reports the anonymous identity if PASSCRED is enabled later.
class UnixMessageCredentials {
    int32_t pid = 0;
    uint32_t uid = 65534, gid = 65534;
    bool captured = false;

  public:
    int read(Task&, uint64_t pointer, size_t length);
    void capture(const Task&);
    size_t write(Task&, uint64_t pointer, size_t capacity, uint32_t& flags) const;
};
} // namespace ax
