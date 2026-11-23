// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/drivers/audio/pcm.hpp
 * @brief   PCM character device declarations.
 * @author  frankischilling
 * @date    2026-11-21
 *
 * Provides device operations for PCM playback and capture.
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
#include "fs/vfs.hpp"

namespace ax::Pcm {
inline constexpr uint32_t sync_request = 0x5001;
inline constexpr unsigned output_period_bytes = page_size, output_periods = 14;

struct OutputState {
    unsigned queued, space;
    bool running, fault;
};

bool initialize();
int open(const Handle&);
void close(const Handle&);
bool output_available();
bool output_busy();
int open_output();
void close_output();
int reset_output();
int start_output();
int drain_output();
OutputState output_state();
int64_t queue_output(const void*, size_t);
bool ready(const Handle&, bool write);
int64_t read(void*, size_t);
int64_t write(const void*, size_t);
int64_t ioctl(const Handle&, uint64_t request, uint64_t argument);
int drain_status();
void poll();
void shutdown();
} // namespace ax::Pcm
