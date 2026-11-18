// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "core/base.hpp"

namespace ax {
struct Frame;

int64_t signalfd_syscall(const Frame&);
} // namespace ax
