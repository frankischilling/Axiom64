// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/mm/tlb_batch.hpp
 * @brief   Defer page reuse until cached translations have been invalidated.
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
#include "arch/x86_64/tlb.hpp"
#include "core/base.hpp"

namespace ax {
// Clear or replace each mapping before adding its page. Finish the batch
// before returning, even for changes to mappings that own no physical pages.
class TlbBatch {
  public:
    explicit TlbBatch(uint64_t root) : root_(root) {
    }

    void retire(uint64_t page) {
        pages_[count_++] = page;
        if (count_ == capacity)
            finish();
    }

    void finish() {
        sync_user_translations(root_);
        for (unsigned i = 0; i < count_; ++i)
            page_free(pages_[i]);
        count_ = 0;
    }

  private:
    static constexpr unsigned capacity = 128;
    uint64_t root_, pages_[capacity];
    unsigned count_ = 0;
};
} // namespace ax
