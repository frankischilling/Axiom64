// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/arch/x86_64/tlb.hpp
 * @brief   Request a page invalidation on a remote CPU.
 * @author  frankischilling
 * @date    2026-11-22
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
#include <stdint.h>

namespace ax {
constexpr uint64_t all_user_translations = UINT64_MAX;

// Switches and invalidations require interrupts disabled. The caller
// serializes page-table writers and keeps the root and its storage alive.
void register_tlb_cpu(uint32_t apic_id);
void unregister_tlb_cpu();
void switch_address_space(uint64_t root);
bool address_space_loaded(uint64_t root);
bool invalidate_user_translations(uint64_t root, uint64_t address = all_user_translations,
                                  unsigned* remote_targets = nullptr);
void service_tlb_ipi();

// Normal memory operations cannot release a mapping if a CPU did not confirm
// invalidation. The diagnostic probe can instead retain its private pages.
void sync_user_translations(uint64_t root, uint64_t address = all_user_translations);

inline void invalidate_local_page(uint64_t address) {
    asm volatile("invlpg (%0)" : : "r"(address) : "memory");
}
} // namespace ax
