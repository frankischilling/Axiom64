// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/ipc/signal_descriptor.hpp
 * @brief   Signal descriptor interface.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Declares signalfd creation, reconfiguration, signal reads, and readiness
 * operations.
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
struct SignalDescriptor {
    uint64_t mask;
};

struct SignalDescriptorRecord {
    uint32_t signal;
    int32_t error, code;
    uint32_t sender, uid;
    int32_t fd;
    uint32_t timer, band, overrun, trap;
    int32_t status, value;
    uint64_t pointer, user_time, system_time, fault_address;
    uint8_t reserved[48];
};

static_assert(sizeof(SignalDescriptorRecord) == 128);
static_assert(offsetof(SignalDescriptorRecord, fault_address) == 72);

struct Handle;
struct Task;

Handle* open_signal_descriptor(uint64_t mask, bool nonblocking, int& error);
bool signal_descriptor_ready(const SignalDescriptor&, const Task&);
bool signal_descriptor_take(const SignalDescriptor&, Task&, SignalDescriptorRecord&);
} // namespace ax
