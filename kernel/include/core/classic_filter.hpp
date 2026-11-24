// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/core/classic_filter.hpp
 * @brief   Classic BPF programs for packet and syscall filtering.
 * @author  frankischilling
 * @date    2026-11-24
 *
 * Copyright (C) 2026 frankischilling
 */
#pragma once
#include "core/base.hpp"

namespace ax {
struct FilterInstruction {
    uint16_t code;
    uint8_t jump_true, jump_false;
    uint32_t value;
};

static_assert(sizeof(FilterInstruction) == 8);
constexpr unsigned max_classic_filter_instructions = 4096;

enum class FilterContext { packet, syscall };

struct FilterInput {
    const uint8_t* data;
    size_t length;
    uint32_t protocol = 0, type = 0, interface = 0;
};

// The caller supplies one mask per instruction for forward scratch validation.
bool validate_classic_filter(const FilterInstruction*, unsigned, uint16_t* masks, FilterContext,
                             size_t input_size = 0);
uint32_t run_classic_filter(const FilterInstruction*, unsigned, const FilterInput&, FilterContext);
} // namespace ax
