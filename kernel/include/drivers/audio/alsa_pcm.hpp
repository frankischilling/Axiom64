// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/drivers/audio/alsa_pcm.hpp
 * @brief   Linux ALSA playback device entry points.
 * @author  frankischilling
 * @date    2026-11-22
 *
 * Exposes PCM and control ioctls over the shared HD Audio playback engine.
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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
 * Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://gnu.org/licenses/>.
 */
#pragma once
#include <stddef.h>
#include <stdint.h>

namespace ax {
struct Task;
}

namespace ax::Alsa {
inline constexpr uint32_t drain_request = 0x4144, write_frames_request = 0x40184150;
int open();
void close();
bool ready();
bool transfer_ready();
int64_t write(const void*, size_t);
int64_t control_ioctl(uint64_t request, uint64_t argument);
int64_t playback_ioctl(Task&, uint64_t request, uint64_t argument);
int drain_status();
} // namespace ax::Alsa
