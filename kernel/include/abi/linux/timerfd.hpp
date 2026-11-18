// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "core/base.hpp"

namespace ax {
struct Frame;
struct Timerfd;

int64_t timerfd_syscall(const Frame&);
int64_t timerfd_ioctl(Timerfd&, uint32_t request, uint64_t argument);
} // namespace ax
