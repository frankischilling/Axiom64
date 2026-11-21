// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/drivers/audio/hda.hpp
 * @brief   High Definition Audio transport declarations.
 * @author  frankischilling
 * @date    2026-11-21
 *
 * Describes controller and stream operations used by the PCM device.
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

namespace ax::Hda {
enum class Direction { playback, capture };

struct BufferDescriptor {
    uint64_t address;
    uint32_t length, flags;
};

static_assert(sizeof(BufferDescriptor) == 16);

void initialize();
bool available(Direction);
bool supports(Direction, unsigned rate, unsigned channels);
bool prepare(Direction, unsigned rate, unsigned channels, uint64_t descriptors, unsigned count,
             unsigned bytes);
bool run(Direction, bool);
uint32_t position(Direction);
bool failed(Direction);
void shutdown();
} // namespace ax::Hda
