// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

void tcp_maxseg_options(int native);

// Both Internet domains exercise the same option and reconnect contract.
void tcp_maxseg_options_family(int native, int family);
