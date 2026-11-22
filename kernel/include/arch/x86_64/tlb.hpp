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
enum class TlbResult { idle, pending, invalidated, inactive, unsupported };

// A serialized sender owns the arguments and a single recipient services them.
// Only queue lower-half, non-global pages. Keep the root alive until the
// request completes, even if the sender times out.
class TlbRequest {
  public:
    bool submit(uint64_t root, uint64_t address);
    TlbResult result() const;
    void service();

  private:
    uint64_t root_ = 0;
    uint64_t address_ = 0;
    TlbResult result_ = TlbResult::idle;
};

inline void invalidate_local_page(uint64_t address) {
    asm volatile("invlpg (%0)" : : "r"(address) : "memory");
}
} // namespace ax
