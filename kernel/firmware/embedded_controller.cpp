// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/firmware/embedded_controller.cpp
 * @brief   Reads the ACPI embedded controller through its command and data ports.
 * @author  frankischilling
 * @date    2026-11-23
 *
 * Copyright (C) 2026 frankischilling
 */
#include "firmware/embedded_controller.hpp"
#include "core/base.hpp"

namespace ax::Acpi {
namespace {
constexpr uint8_t output_full = 1, input_full = 2, command_read = 0x80, command_write = 0x81;
constexpr unsigned poll_delay_us = 50, max_waits = 1000;

enum class Ready { input, read_request, output };

bool wait_for_port(const EmbeddedControllerPorts& ports, const EmbeddedControllerIo& io,
                   Ready phase, unsigned& remaining, uint8_t* ready_status = nullptr) {
    for (;;) {
        const uint8_t status = io.read(io.context, ports.command);
        // Never treat pending output as this read's response. A write checks
        // only its own input buffer and leaves unrelated output untouched.
        if (status == UINT8_MAX || (phase == Ready::read_request && (status & output_full)))
            return false;
        if (phase == Ready::output ? (status & output_full) : !(status & input_full)) {
            if (ready_status)
                *ready_status = status;
            return true;
        }
        if (!remaining || !io.delay_us(io.context, poll_delay_us))
            return false;
        --remaining;
    }
}

bool valid_transfer(const EmbeddedControllerPorts& ports, const EmbeddedControllerIo& io,
                    uint8_t offset, const uint8_t* data, size_t length) {
    return ports.data && ports.command && ports.data != ports.command && io.read && io.write &&
           io.delay_us && data && length && length <= 256u - offset;
}

bool begin_byte(const EmbeddedControllerPorts& ports, const EmbeddedControllerIo& io,
                uint8_t command, uint8_t offset, unsigned& remaining) {
    const auto phase = command == command_read ? Ready::read_request : Ready::input;
    uint8_t idle_status;
    if (!wait_for_port(ports, io, Ready::input, remaining, &idle_status))
        return false;
    if (phase == Ready::read_request && (idle_status & output_full)) {
        // No read command is in flight. Discard one stale byte and require
        // the port to clear before sending a request that expects a response.
        io.read(io.context, ports.data);
        if (!wait_for_port(ports, io, Ready::read_request, remaining))
            return false;
    }
    io.write(io.context, ports.command, command);
    if (!wait_for_port(ports, io, phase, remaining))
        return false;
    io.write(io.context, ports.data, offset);
    return true;
}
} // namespace

bool read_embedded_controller(const EmbeddedControllerPorts& ports, const EmbeddedControllerIo& io,
                              uint8_t offset, uint8_t* bytes, size_t length) {
    if (!valid_transfer(ports, io, offset, bytes, length))
        return false;

    // ACPI 6.6 section 12.3.1. Wait for the controller to consume each input.
    uint8_t data[256];
    unsigned remaining = max_waits;
    for (size_t i = 0; i < length; ++i) {
        if (!begin_byte(ports, io, command_read, uint8_t(offset + i), remaining) ||
            !wait_for_port(ports, io, Ready::output, remaining))
            return false;
        data[i] = io.read(io.context, ports.data);
    }
    memcpy(bytes, data, length);
    return true;
}

bool write_embedded_controller(const EmbeddedControllerPorts& ports, const EmbeddedControllerIo& io,
                               uint8_t offset, const uint8_t* bytes, size_t length) {
    if (!valid_transfer(ports, io, offset, bytes, length))
        return false;

    // ACPI 6.6 section 12.3.2. Completion requires the final data byte to be consumed.
    unsigned remaining = max_waits;
    for (size_t i = 0; i < length; ++i) {
        if (!begin_byte(ports, io, command_write, uint8_t(offset + i), remaining) ||
            !wait_for_port(ports, io, Ready::input, remaining))
            return false;
        io.write(io.context, ports.data, bytes[i]);
        if (!wait_for_port(ports, io, Ready::input, remaining))
            return false;
    }
    return true;
}
} // namespace ax::Acpi
