// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

namespace ax::net {
// Acquire before opening configuration or resolver journals. The permanent
// private lock inode is never removed; final close releases its flock.
// Call close explicitly to observe errors. Destruction performs best-effort close.
class Ownership {
  public:
    Ownership() = default;

    ~Ownership();

    Ownership(const Ownership&) = delete;

    Ownership& operator=(const Ownership&) = delete;

    int open(const char* runtime);

    int close();

  private:
    int descriptor_ = -1;
};
} // namespace ax::net
