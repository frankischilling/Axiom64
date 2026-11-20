// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    userspace/net/manager/ownership.hpp
 * @brief   Network manager ownership interface.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Defines the ownership state used to reconcile manager changes with external
 * configuration.
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
