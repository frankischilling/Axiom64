// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    userspace/tests/net/tcp_maxseg.h
 * @brief   TCP segment size test helpers.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Provides shared operations and checks for the TCP_MAXSEG socket option.
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

void tcp_maxseg_options(int native);

// Both Internet domains exercise the same option and reconnect contract.
void tcp_maxseg_options_family(int native, int family);
