// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/ipc/unix_control.hpp
 * @brief   Unix ancillary message interface.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Defines ancillary state and declares import and emission of control messages.
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
#include "ipc/unix_credentials.hpp"

namespace ax {
class UnixRights;
// Success transfers captured descriptions to rights. Failure releases every
// partial capture and leaves the caller's control unchanged.
int unix_read_control(Task&, uint64_t pointer, size_t length, UnixMessageCredentials&,
                      UnixRights*& rights);
size_t unix_write_control(Task&, const UnixMessageCredentials*, const UnixRights*,
                          bool pass_credentials, uint64_t pointer, size_t capacity, bool cloexec,
                          uint32_t& flags);
} // namespace ax
