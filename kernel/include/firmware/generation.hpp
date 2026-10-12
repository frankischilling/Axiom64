// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "core/base.hpp"

namespace ax::Firmware {
using Read = bool (*)(void*, uint16_t, size_t, void*, size_t);

// QEMU's fw_cfg generation file is supplied by the current hypervisor instance,
// rather than restored from a guest memory snapshot. Identifiers are not entropy.
class Generation {
    Read reader = nullptr;
    void* context = nullptr;
    uint16_t selector = 0;
    uint32_t slot = 0;
    uint8_t previous[16]{};
    bool live = false;

    bool discover();

    bool identifier(uint8_t[16]);

  public:
    bool initialize(Read, void*, uint8_t[16]);

    // Returns 1 for a changed identifier, 0 for unchanged/absent, -1 on failure.
    int poll(uint8_t[16]);

    bool active() const {
        return live;
    }
};
} // namespace ax::Firmware
