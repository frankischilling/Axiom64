// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/drivers/graphics/drm_scanout.hpp
 * @brief   Fixed scanout device interface.
 * @author  frankischilling
 * @date    2026-11-23
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
#include "core/base.hpp"

namespace ax {
struct BootFramebuffer;
struct Handle;

namespace DrmScanout {
bool init(const BootFramebuffer&, bool virtio);
int open(Handle&);
void close(Handle&);
int64_t ioctl(Handle&, uint64_t request, uint64_t argument);
int mapping(const Handle&, uint64_t offset, size_t size, int prot, int flags, uint64_t& address);
} // namespace DrmScanout
} // namespace ax
