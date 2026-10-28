// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <cstddef>

namespace multicast_test {
void allocation_limit(unsigned successful_allocations);
size_t live_allocations();
} // namespace multicast_test
