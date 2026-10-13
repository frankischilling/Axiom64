// SPDX-License-Identifier: GPL-3.0-or-later
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
// A live process, held lease, foreign display or damaged metadata fails closed.
int desktop_seat_recover(void);

#endif
