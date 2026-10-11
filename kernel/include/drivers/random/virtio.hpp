// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <stdint.h>

namespace ax {
void virtio_rng_init(bool trusted);
void virtio_rng_poll(uint64_t ticks);
} // namespace ax
