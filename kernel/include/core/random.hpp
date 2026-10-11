// SPDX-License-Identifier: GPL-3.0-or-later
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
