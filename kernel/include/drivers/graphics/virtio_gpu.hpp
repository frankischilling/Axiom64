// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/drivers/graphics/virtio_gpu.hpp
 * @brief   Declares the Virtio GPU scanout backend.
 * @author  frankischilling
 * @date    2026-11-23
 *
 * Connects a Virtio display to the framebuffer device and timer.
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

const BootFramebuffer* virtio_gpu_scanout_init();
bool virtio_gpu_request_refresh();
void virtio_gpu_poll(uint64_t now);
} // namespace ax
