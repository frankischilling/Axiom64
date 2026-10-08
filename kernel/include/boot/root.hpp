// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

namespace ax {
// Select and validate the root before starting Ring 3 init.
void boot_root_init(const char* command_line);
} // namespace ax
