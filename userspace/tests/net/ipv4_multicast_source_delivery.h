// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    userspace/tests/net/ipv4_multicast_source_delivery.h
 * @brief   IPv4 multicast delivery test helpers.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Provides membership operations and receive checks for source-filtered
 * multicast traffic.
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

void ipv4_source_delivery(const unsigned indices[2], void (*barrier)(unsigned, int));
