// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/abi/linux/resource.hpp
 * @brief   Linux resource-limit ABI declarations.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Declares syscall handlers for reading and updating task resource limits.
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
#include "process/cpu.hpp"

namespace ax {
struct ResourceUsage {
    struct Timeval {
        int64_t seconds, microseconds;
    } user, system;

    int64_t counters[14];
};

static_assert(sizeof(ResourceUsage) == 144);

ResourceUsage linux_resource_usage(CpuUsage);
int64_t resource_usage_syscall(int who, uint64_t output);
int64_t system_information_syscall(uint64_t output);
int64_t resource_syscall(Frame*);
} // namespace ax
