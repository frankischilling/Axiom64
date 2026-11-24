// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/process/pending_signals.hpp
 * @brief   Pending signal queue interface.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Defines queued signal information and declares helpers for selecting and
 * consuming pending signals.
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
struct SignalData {
    int sender = 0, code = 0, status = 0;
    uint64_t address = 0;
    uint32_t uid = 0;
    uint64_t child_user_ticks = 0;
    uint64_t child_system_ticks = 0;
    uint64_t value = 0;
    int error = 0;
    int syscall_number = 0;
    uint32_t syscall_architecture = 0;
};

struct QueuedSignal;

class PendingSignals {
  public:
    uint64_t mask() const {
        return mask_;
    }

    int push(int number, const SignalData&, uint32_t uid, uint64_t limit);

    SignalData take(int number);

    void discard(uint64_t mask);

  private:
    uint64_t mask_ = 0;
    QueuedSignal* head_ = nullptr;
    QueuedSignal* tail_ = nullptr;
};
} // namespace ax
