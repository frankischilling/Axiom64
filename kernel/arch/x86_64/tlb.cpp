// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/arch/x86_64/tlb.cpp
 * @brief   Acknowledge remote page invalidation requests.
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
#include "arch/x86_64/tlb.hpp"
#include "core/base.hpp"

namespace ax {
bool TlbRequest::submit(uint64_t root, uint64_t address) {
    if (!root || (root & ~page_mask) || address >= user_limit || address % page_size ||
        result() == TlbResult::pending)
        return false;
    root_ = root;
    address_ = address;
    __atomic_store_n(&result_, TlbResult::pending, __ATOMIC_RELEASE);
    return true;
}

TlbResult TlbRequest::result() const {
    return __atomic_load_n(&result_, __ATOMIC_ACQUIRE);
}

void TlbRequest::service() {
    if (result() != TlbResult::pending)
        return;
    uint64_t cr4;
    asm volatile("mov %%cr4,%0" : "=r"(cr4));
    constexpr uint64_t pcide = 1ull << 17;
    auto result = TlbResult::unsupported;
    if (!(cr4 & pcide)) {
        result = TlbResult::inactive;
        if ((read_cr3() & page_mask) == root_) {
            invalidate_local_page(address_);
            result = TlbResult::invalidated;
        }
    }
    __atomic_store_n(&result_, result, __ATOMIC_RELEASE);
}
} // namespace ax
