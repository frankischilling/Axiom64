// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/ipc/socket_registry.hpp
 * @brief   IPC socket registry interface.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Declares the internal registry operations that track sockets across creation
 * and release.
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
#include "ipc/ipc.hpp"

namespace ax {
// Private to IPC: allocation/close and namespace lookup share this bounded pool.
extern Socket sockets[256];
} // namespace ax
