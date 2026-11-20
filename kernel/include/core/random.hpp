// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/core/random.hpp
 * @brief   Kernel entropy interface.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Declares random readiness, seeded byte generation, and entropy collection
 * operations.
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
#include <stddef.h>
#include <stdint.h>

namespace ax {
namespace random {
class SeedSource;
}

// Serialized by the current single-CPU, interrupt-disabled kernel execution model.
// Initialize once during boot, before any output or input-mixing call.
void random_init(bool trust_cpu, bool trust_virtio = false);
void random_refresh(uint64_t ticks);
bool random_ready();
unsigned random_entropy_count();
void random_credit(unsigned bits); // Caller must validate a trusted source or CAP_SYS_ADMIN.
int random_reseed();
bool random_sample_source(random::SeedSource&, const char* name, bool trusted);
int random_read(void*, size_t, bool insecure = false); // 0 or negative errno.
void random_mix(const void*, size_t); // User-controlled data never establishes readiness.
} // namespace ax
