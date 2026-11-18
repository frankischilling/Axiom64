// SPDX-License-Identifier: GPL-3.0-or-later
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
