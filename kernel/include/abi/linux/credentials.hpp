// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/abi/linux/credentials.hpp
 * @brief   Linux credential ABI declarations.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Declares the Linux-facing handlers for user IDs, group IDs, and capability
 * sets.
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
int64_t credential_syscall(Frame*);
}
