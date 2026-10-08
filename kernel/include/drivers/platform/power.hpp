// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

namespace ax {
// Best effort for the tested PIIX4 platform; the caller halts if power remains on.
void platform_poweroff();
} // namespace ax
