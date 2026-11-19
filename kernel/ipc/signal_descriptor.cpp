// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/ipc/signal_descriptor.cpp
 * @brief   Signal descriptor operations.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Tracks signalfd masks and delivers matching pending signals through
 * descriptor reads.
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
#include "ipc/signal_descriptor.hpp"
#include "fs/vfs.hpp"
#include "process/signals.hpp"

namespace ax {
Handle* open_signal_descriptor(uint64_t mask, bool nonblocking, int& error) {
    error = -12;
    auto descriptor = static_cast<SignalDescriptor*>(alloc(sizeof(SignalDescriptor)));
    if (!descriptor)
        return nullptr;
    *descriptor = {mask};
    auto handle = open_handle(nullptr, 2 | (nonblocking ? 04000 : 0), &error);
    if (!handle) {
        release(descriptor);
        return nullptr;
    }
    handle->signal_descriptor = descriptor;
    return handle;
}

bool signal_descriptor_ready(const SignalDescriptor& descriptor, const Task& task) {
    return signal_pending_for(task, descriptor.mask);
}

bool signal_descriptor_take(const SignalDescriptor& descriptor, Task& task,
                            SignalDescriptorRecord& record) {
    SignalData data;
    int signal = take_pending_signal(task, descriptor.mask, data);
    if (!signal)
        return false;
    record = {};
    record.signal = signal;
    record.error = data.error;
    record.code = data.code;
    if (data.code > 0 && (signal == 4 || signal == 5 || signal == 7 || signal == 8 || signal == 11))
        record.fault_address = data.address;
    else {
        record.sender = data.sender;
        record.uid = data.uid;
        if (data.code < 0 && data.code != -6) {
            record.value = int32_t(data.value);
            record.pointer = data.value;
        }
        if (signal == 17 && data.code > 0) {
            record.status = data.status;
            record.user_time = data.child_user_ticks;
            record.system_time = data.child_system_ticks;
        }
    }
    return true;
}
} // namespace ax
