// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/firmware/generation.cpp
 * @brief   Firmware generation identifier.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Reads the firmware generation input used to refresh random state after guest
 * restoration.
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
#include "firmware/generation.hpp"
#include "core/random/primitives.hpp"

namespace ax::Firmware {
static uint32_t big(const uint8_t* bytes, size_t length) {
    uint32_t value = 0;
    for (size_t i = 0; i < length; i++)
        value = (value << 8) | bytes[i];
    return value;
}

static bool name(const uint8_t* entry) {
    constexpr char generation[] = "etc/vmgenid_guid";
    return !memcmp(entry + 8, generation, sizeof(generation));
}

static bool valid(const uint8_t* entry) {
    uint32_t key = big(entry + 4, 2);
    return name(entry) && big(entry, 4) == 4096 && key >= 0x20 && key < 0x4000 &&
           !big(entry + 6, 2);
}

bool Generation::discover() {
    uint8_t header[4];
    if (!reader || !reader(context, 0, 0, header, 4) || memcmp(header, "QEMU", 4) ||
        !reader(context, 0x19, 0, header, 4))
        return false;
    uint32_t count = big(header, 4);
    if (!count || count > 256)
        return false;
    uint16_t found = 0;
    uint32_t found_slot = 0;
    for (uint32_t i = 0; i < count; i++) {
        uint8_t entry[64];
        if (!reader(context, 0x19, 4 + size_t(i) * 64, entry, sizeof(entry)))
            return false;
        bool terminated = false;
        for (size_t j = 8; j < 64; j++)
            terminated |= !entry[j];
        if (!terminated)
            return false;
        if (!name(entry))
            continue;
        if (found || !valid(entry))
            return false;
        found = big(entry + 4, 2);
        found_slot = i;
    }
    if (!found)
        return false;
    selector = found;
    slot = found_slot;
    return true;
}

bool Generation::identifier(uint8_t output[16]) {
    uint8_t entry[64];
    if (!reader(context, 0x19, 4 + size_t(slot) * 64, entry, sizeof(entry)))
        return false;
    if (!valid(entry) || big(entry + 4, 2) != selector) {
        if (!discover())
            return false;
    }
    uint8_t first[16]{}, second[16]{};
    bool success = false;
    // A restore can resume in the middle of a read. Require a stable pair and
    // retry a bounded number of times before publishing an identifier.
    for (unsigned attempt = 0; attempt < 4; attempt++) {
        if (!reader(context, selector, 40, first, sizeof(first)) ||
            !reader(context, selector, 40, second, sizeof(second)))
            break;
        if (!memcmp(first, second, sizeof(first))) {
            memcpy(output, first, sizeof(first));
            success = true;
            break;
        }
    }
    random::erase(first, sizeof(first));
    random::erase(second, sizeof(second));
    return success;
}

bool Generation::initialize(Read read, void* opaque, uint8_t output[16]) {
    reader = read;
    context = opaque;
    live = false;
    selector = 0;
    random::erase(previous, sizeof(previous));
    if (!discover() || !identifier(output))
        return false;
    memcpy(previous, output, sizeof(previous));
    live = true;
    return true;
}

int Generation::poll(uint8_t output[16]) {
    if (!live)
        return 0;
    uint8_t next[16]{};
    if (!identifier(next)) {
        random::erase(next, sizeof(next));
        return -1;
    }
    bool changed = memcmp(previous, next, sizeof(previous));
    if (changed) {
        memcpy(previous, next, sizeof(previous));
        memcpy(output, next, sizeof(previous));
    }
    random::erase(next, sizeof(next));
    return changed;
}
} // namespace ax::Firmware
