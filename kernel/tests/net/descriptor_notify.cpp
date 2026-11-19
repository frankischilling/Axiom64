// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file
 */
#include "io/descriptor_wait.hpp"

namespace ax {
// Component tests run the network stack without the process scheduler.
void descriptor_wait_notify(const void*, uint32_t) {
}
} // namespace ax
