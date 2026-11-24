// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/security/seccomp.hpp
 * @brief   Install and enforce Linux syscall filters.
 * @author  frankischilling
 * @date    2026-11-24
 *
 * Copyright (C) 2026 frankischilling
 */
#pragma once
#include "core/base.hpp"

namespace ax {
struct Task;

void seccomp_inherit(Task& child, const Task& parent);
void seccomp_release(Task&);
int64_t seccomp_syscall(Task&, uint32_t operation, uint32_t flags, uint64_t argument);
int64_t seccomp_set_mode(Task&, uint64_t mode, uint64_t program);
bool seccomp_may_dispatch(Task&, const Frame&, int64_t& result);
} // namespace ax
