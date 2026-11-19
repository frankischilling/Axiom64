// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    userspace/desktop/seat.h
 * @brief   Desktop seat interface.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Declares the seat and session checks used by the desktop launcher.
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
#ifndef AXIOM64_DESKTOP_SEAT_H
#define AXIOM64_DESKTOP_SEAT_H

#include "../accounts/auth.h"

struct desktop_seat;

// Only the privileged, authenticated session supervisor calls these functions.
// Xorg retains root-only device access; its clients receive the user's complete
// profile and a private cookie. A permanent open-description lock owns the seat.
int desktop_seat_start(const struct account_profile*, struct desktop_seat**);

int desktop_seat_observe(struct desktop_seat*);

// Stop/reap owned processes, clear framebuffer pixels and revoke authorization.
int desktop_seat_stop(struct desktop_seat*);

// Recover a dead supervisor's protected seat before showing a login prompt.
// A matching boot/process incarnation, held lease, foreign display or damaged
// metadata fails closed. Recovery never signals saved numeric process IDs.
int desktop_seat_recover(void);

#endif
