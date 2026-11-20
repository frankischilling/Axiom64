// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    userspace/net/manager/ownership.cpp
 * @brief   Network manager resource ownership.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Tracks configuration resources belonging to the manager across interfaces and
 * transitions.
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
#include "net/manager/ownership.hpp"
#include "net/config/saved.hpp"
#include <errno.h>
#include <unistd.h>

namespace ax::net {
Ownership::~Ownership() {
    close();
}

int Ownership::open(const char* runtime) {
    if (descriptor_ >= 0)
        return EALREADY;
    return saved::lock(runtime, "manager.lock", descriptor_);
}

int Ownership::close() {
    int descriptor = descriptor_;
    descriptor_ = -1;
    return descriptor >= 0 && ::close(descriptor) < 0 ? errno : 0;
}
} // namespace ax::net
