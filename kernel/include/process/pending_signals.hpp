// SPDX-License-Identifier: GPL-3.0-or-later
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
