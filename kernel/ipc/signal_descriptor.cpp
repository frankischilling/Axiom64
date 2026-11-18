// SPDX-License-Identifier: GPL-3.0-or-later
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
