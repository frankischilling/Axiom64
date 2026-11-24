// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/firmware/embedded_controller.hpp
 * @brief   Declares polled reads from an ACPI embedded controller.
 * @author  frankischilling
 * @date    2026-11-23
 *
 * Copyright (C) 2026 frankischilling
 */
#pragma once
#include "firmware/acpi.hpp"

namespace ax::Acpi {
struct EmbeddedControllerPorts {
    uint16_t data, command;
    bool global_lock = false;
};

struct EmbeddedControllerIo {
    void* context;
    uint8_t (*read)(void*, uint16_t port);
    void (*write)(void*, uint16_t port, uint8_t value);
    bool (*delay_us)(void*, unsigned us);
};

// The caller owns the validated ports for the entire transaction. Shared
// controllers require the ACPI Global Lock. An error leaves bytes unchanged.
bool read_embedded_controller(const EmbeddedControllerPorts&, const EmbeddedControllerIo&,
                              uint8_t offset, uint8_t* bytes, size_t length);

// A failed write can leave earlier bytes changed.
bool write_embedded_controller(const EmbeddedControllerPorts&, const EmbeddedControllerIo&,
                               uint8_t offset, const uint8_t* bytes, size_t length);
} // namespace ax::Acpi
