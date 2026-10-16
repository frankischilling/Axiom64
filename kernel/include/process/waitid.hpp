// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "process/task.hpp"

namespace ax {
int wait_information_selector(const Task&, unsigned type, uint32_t id, unsigned options,
                              int& selected);

int64_t wait_information(Task&, unsigned type, int selected, uint64_t information, unsigned options,
                         uint64_t usage);

bool wait_information_ready(const Task&);
} // namespace ax
