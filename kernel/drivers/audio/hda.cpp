// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/drivers/audio/hda.cpp
 * @brief   Polled Intel High Definition Audio controller driver.
 * @author  frankischilling
 * @date    2026-11-21
 *
 * Discovers codec paths and owns controller and stream registers.
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
#include "drivers/audio/hda.hpp"
#include "core/time.hpp"
#include "drivers/platform/pci.hpp"
#include "drivers/platform/poll.hpp"
#include "mm/dma.hpp"

namespace ax::Hda {
namespace {
using DevicePoll::wait;
constexpr unsigned capabilities = 0x00, global_control = 0x08, codec_status = 0x0e;
constexpr unsigned interrupt_control = 0x20, corb_base = 0x40, corb_write = 0x48, corb_read = 0x4a;
constexpr unsigned corb_control = 0x4c, corb_status = 0x4d, corb_size = 0x4e;
constexpr unsigned rirb_base = 0x50, rirb_write = 0x58, response_count = 0x5a;
constexpr unsigned rirb_control = 0x5c, rirb_status = 0x5d, rirb_size = 0x5e;
constexpr unsigned position_base = 0x70;
constexpr unsigned stream_base = 0x80, stream_stride = 0x20;
constexpr unsigned stream_control = 0, stream_tag = 2, stream_status = 3, link_position = 4;
constexpr unsigned cyclic_length = 8, last_descriptor = 0x0c, stream_format = 0x12, bdl_base = 0x18;
constexpr uint8_t stream_run = 2, stream_reset = 1, stream_errors = 0x18;
constexpr unsigned timeout = 10;
constexpr unsigned response_offset = 2048;

struct Path {
    uint8_t codec = 0, group = 0, converter = 0, pin = 0, selector = 0;
    uint32_t converter_caps = 0, pin_caps = 0, pin_features = 0, formats = 0;
};

struct Stream {
    unsigned offset = 0;
    Path path{};
};

Stream streams[2];
PciFunction function{};
volatile uint8_t* mmio;
uint64_t rings;
unsigned corb_head, rirb_head;
bool healthy;

Stream& stream(Direction direction) {
    return streams[direction == Direction::capture];
}

template <typename T> T read(unsigned offset) {
    return *reinterpret_cast<volatile T*>(mmio + offset);
}

template <typename T> void write(unsigned offset, T value) {
    *reinterpret_cast<volatile T*>(mmio + offset) = value;
}

void address(unsigned offset, uint64_t value) {
    write<uint32_t>(offset, value);
    write<uint32_t>(offset + 4, value >> 32);
}

bool reset_controller() {
    write<uint32_t>(interrupt_control, 0);
    write<uint32_t>(global_control, 0);
    if (!wait([] { return !(read<uint32_t>(global_control) & 1); }, timeout) ||
        !clock_delay_us(100))
        return false;
    write<uint32_t>(global_control, 1);
    return wait([] { return read<uint32_t>(global_control) & 1; }, timeout) && clock_delay_us(550);
}

bool configure_rings() {
    if (!(read<uint8_t>(corb_size) & 0x40) || !(read<uint8_t>(rirb_size) & 0x40))
        return false;
    address(corb_base, rings);
    address(rirb_base, rings + response_offset);
    write<uint8_t>(corb_size, 2);
    write<uint8_t>(rirb_size, 2);
    write<uint16_t>(corb_write, 0);
    write<uint16_t>(corb_read, 0x8000);
    if (!wait([] { return read<uint16_t>(corb_read) & 0x8000; }, timeout))
        return false;
    write<uint16_t>(corb_read, 0);
    if (!wait([] { return read<uint16_t>(corb_read) == 0; }, timeout))
        return false;
    write<uint16_t>(rirb_write, 0x8000);
    if (!wait([] { return !(read<uint16_t>(rirb_write) & 255); }, timeout))
        return false;
    write<uint16_t>(response_count, 1);
    write<uint8_t>(corb_status, 1);
    write<uint8_t>(rirb_status, 5);
    // Keep response status active for acknowledgement while INTCTL masks IRQ delivery.
    write<uint8_t>(rirb_control, 7);
    write<uint8_t>(corb_control, 2);
    if (read<uint8_t>(rirb_control) != 7 || read<uint8_t>(corb_control) != 2)
        return false;
    corb_head = rirb_head = 0;
    return true;
}

bool command(unsigned codec, unsigned node, unsigned verb, uint32_t& result) {
    corb_head = (corb_head + 1) & 255;
    auto* commands = static_cast<uint32_t*>(physical(rings));
    auto* responses = static_cast<volatile uint32_t*>(physical(rings + response_offset));
    commands[corb_head] = (codec << 28) | (node << 20) | verb;
    asm volatile("mfence" ::: "memory");
    write<uint16_t>(corb_write, corb_head);
    if (!wait(
            [] {
                return (read<uint16_t>(rirb_write) & 255) != rirb_head ||
                       (read<uint8_t>(corb_status) & 1) || (read<uint8_t>(rirb_status) & 4);
            },
            timeout) ||
        (read<uint8_t>(corb_status) & 1) || (read<uint8_t>(rirb_status) & 4)) {
        healthy = false;
        return false;
    }
    asm volatile("mfence" ::: "memory");
    rirb_head = (rirb_head + 1) & 255;
    const auto response_tag = responses[rirb_head * 2 + 1];
    if ((response_tag & 31) != codec || (read<uint16_t>(rirb_write) & 255) != rirb_head) {
        healthy = false;
        return false;
    }
    result = responses[rirb_head * 2];
    write<uint8_t>(rirb_status, 1);
    return true;
}

bool verb(unsigned codec, unsigned node, unsigned operation, unsigned data = 0) {
    uint32_t ignored;
    return healthy && command(codec, node, (operation << 8) | data, ignored);
}

uint32_t query(unsigned codec, unsigned node, unsigned operation, unsigned data = 0) {
    uint32_t reply = 0;
    if (healthy)
        command(codec, node, (operation << 8) | data, reply);
    return reply;
}

uint32_t param(unsigned codec, unsigned node, unsigned field) {
    return query(codec, node, 0xf00, field);
}

int connection(unsigned codec, unsigned node, unsigned target) {
    const auto list = param(codec, node, 0x0e);
    const unsigned bits = list & 0x80 ? 16 : 8;
    const unsigned entries = 32 / bits, range = 1u << (bits - 1);
    unsigned index = 0, previous = 0;
    for (unsigned i = 0; i < (list & 127); i += entries) {
        const auto response = query(codec, node, 0xf02, i);
        for (unsigned j = 0; j < entries && i + j < (list & 127); ++j) {
            const unsigned entry = (response >> (j * bits)) & (2 * range - 1);
            const unsigned current = entry & (range - 1);
            const unsigned first = entry & range ? previous + 1 : current;
            if (first > current || current > 127)
                return -1;
            if (target >= first && target <= current && index + target - first < 16)
                return int(index + target - first);
            index += current + 1 - first;
            previous = current;
        }
    }
    return -1;
}

void find_paths(unsigned codec, unsigned group) {
    const auto widgets = param(codec, group, 4);
    const unsigned begin = (widgets >> 16) & 0xff;
    const unsigned end = min(begin + (widgets & 0xff), 128u);
    for (unsigned pin = begin; pin < end; ++pin) {
        const auto pin_caps = param(codec, pin, 9);
        if (((pin_caps >> 20) & 15) != 4 || (query(codec, pin, 0xf1c) >> 30) == 1)
            continue;
        const auto features = param(codec, pin, 0x0c);
        for (unsigned converter = begin; converter < end; ++converter) {
            const auto caps = param(codec, converter, 9);
            const auto type = (caps >> 20) & 15;
            const bool capture = type == 1;
            if (type > 1 || !caps || streams[capture].path.converter ||
                !(features & (capture ? 0x20 : 0x10)))
                continue;
            const auto selector =
                capture ? connection(codec, converter, pin) : connection(codec, pin, converter);
            const auto format_node = caps & 16 ? converter : group;
            const auto formats = param(codec, format_node, 0x0a);
            if (selector < 0 || !(formats & (1u << 17)) || !(param(codec, format_node, 0x0b) & 1))
                continue;
            streams[capture].path = {uint8_t(codec), uint8_t(group),    uint8_t(converter),
                                     uint8_t(pin),   uint8_t(selector), caps,
                                     pin_caps,       features,          formats};
        }
    }
}

void discover_codecs() {
    const auto present = read<uint16_t>(codec_status) & 0x7fff;
    for (unsigned codec = 0; healthy && codec < 15; ++codec) {
        if (!(present & (1u << codec)))
            continue;
        const auto groups = param(codec, 0, 4);
        const unsigned start = (groups >> 16) & 0xff;
        const unsigned end = min(start + (groups & 0xff), 128u);
        for (unsigned group = start; healthy && group < end; ++group)
            if ((param(codec, group, 5) & 255) == 1)
                find_paths(codec, group);
    }
}

void amplifier(const Path& path, unsigned node, uint32_t caps, bool output, unsigned input_index) {
    if (!(caps & (output ? 4u : 2u)))
        return;
    const auto amp = param(path.codec, caps & 8 ? node : path.group, output ? 0x12 : 0x0d);
    const unsigned gain = min(amp & 127, (amp >> 8) & 127);
    const unsigned control = (output ? 0xb000 : 0x7000) | (input_index << 8) | gain;
    verb(path.codec, node, 0x300, control);
}

bool configure_path(const Path& path, bool capture, unsigned format, unsigned tag) {
    const unsigned codec = path.codec;
    if (!verb(codec, path.group, 0x705) ||
        ((path.converter_caps & (1u << 10)) && !verb(codec, path.converter, 0x705)) ||
        ((path.pin_caps & (1u << 10)) && !verb(codec, path.pin, 0x705)) ||
        !verb(codec, capture ? path.converter : path.pin, 0x701, path.selector))
        return false;
    if (path.pin_features & (1u << 16))
        verb(codec, path.pin, 0x70c, 2);
    amplifier(path, path.converter, path.converter_caps, !capture, capture ? path.selector : 0);
    amplifier(path, path.pin, path.pin_caps, !capture, capture ? 0 : path.selector);
    const unsigned pin_control = capture ? 0x20 : (0x40 | (path.pin_features & 8 ? 0x80 : 0));
    return verb(codec, path.pin, 0x707, pin_control) &&
           verb(codec, path.converter, 0x200, format) &&
           verb(codec, path.converter, 0x706, tag << 4);
}

struct Rate {
    unsigned hz, format, capability;
};

constexpr Rate rates[] = {{11025, 0x4300, 1},
                          {22050, 0x4100, 3},
                          {32000, 0x0a00, 4},
                          {44100, 0x4000, 5},
                          {48000, 0x0000, 6}};

const Rate* rate_info(unsigned rate) {
    for (const auto& entry : rates)
        if (entry.hz == rate)
            return &entry;
    return nullptr;
}

void disable() {
    if (!mmio)
        return;
    write<uint32_t>(interrupt_control, 0);
    write<uint32_t>(global_control, 0);
    const bool stopped = wait([] { return !(read<uint32_t>(global_control) & 1); }, timeout);
    function.write16(4, function.read16(4) & ~4u);
    if (rings && stopped && !(function.read16(4) & 4))
        page_free(rings, 1);
    rings = 0;
    healthy = false;
    mmio = nullptr;
}

void attach(const PciFunction& pci) {
    if (mmio || pci.read16(0x0a) != 0x0403 || pci.read16(0) != 0x8086)
        return;
    PciBar bar{};
    uint64_t base = 0;
    if (pci.probe_bar(0, PciBarSpace::memory, bar) != PciBarStatus::valid ||
        !bar.range(0, page_size, base))
        return;
    mmio = static_cast<volatile uint8_t*>(map_mmio(base, page_size));
    if (!mmio)
        return;
    function = pci;
    const auto original = pci.read16(4);
    pci.write16(4, (original & ~7u) | 0x402);
    if ((pci.read16(4) & 0x407) != 0x402 || !reset_controller()) {
        disable();
        return;
    }
    const auto cap = read<uint16_t>(capabilities);
    const unsigned inputs = (cap >> 8) & 15, outputs = cap >> 12;
    streams[0] = {outputs ? stream_base + inputs * stream_stride : 0, {}};
    streams[1] = {inputs ? stream_base : 0, {}};
    address(position_base, 0);
    rings = Dma::allocate(1, Dma::pci);
    if (!rings) {
        disable();
        return;
    }
    pci.write16(4, (original & ~7u) | 0x406);
    healthy = (pci.read16(4) & 0x407) == 0x406 && configure_rings();
    if (healthy)
        discover_codecs();
    if (!available(Direction::playback) && !available(Direction::capture)) {
        disable();
        return;
    }
    log("hda: codec paths playback=%u capture=%u\n", uint64_t(available(Direction::playback)),
        uint64_t(available(Direction::capture)));
}
} // namespace

void initialize() {
    pci_scan(attach);
}

bool available(Direction direction) {
    const auto& channel = stream(direction);
    return healthy && channel.offset && channel.path.converter;
}

bool supports(Direction direction, unsigned rate, unsigned channels) {
    const auto* entry = rate_info(rate);
    const auto& path = stream(direction).path;
    return available(direction) && entry && (path.formats & (1u << entry->capability)) &&
           (channels == 1 || (channels == 2 && (path.converter_caps & 1)));
}

bool run(Direction direction, bool start) {
    const auto offset = stream(direction).offset;
    if (!mmio || !offset)
        return !start;
    write<uint8_t>(offset + stream_control, start ? stream_run : 0);
    return wait([=] { return bool(read<uint8_t>(offset + stream_control) & stream_run) == start; },
                timeout);
}

bool prepare(Direction direction, unsigned rate, unsigned channels, uint64_t descriptors,
             unsigned count, unsigned bytes) {
    if (!supports(direction, rate, channels) || !run(direction, false))
        return false;
    const auto& channel = stream(direction);
    const auto offset = channel.offset;
    write<uint8_t>(offset + stream_control, stream_reset);
    if (!wait([=] { return read<uint8_t>(offset + stream_control) & stream_reset; }, timeout))
        return false;
    write<uint8_t>(offset + stream_control, 0);
    if (!wait([=] { return !(read<uint8_t>(offset + stream_control) & stream_reset); }, timeout))
        return false;
    write<uint8_t>(offset + stream_status, 0x1c);
    const bool capture = direction == Direction::capture;
    const unsigned tag = capture ? 2 : 1;
    const unsigned format = rate_info(rate)->format | 0x10 | (channels - 1);
    write<uint8_t>(offset + stream_tag, tag << 4);
    write<uint32_t>(offset + cyclic_length, bytes);
    write<uint16_t>(offset + last_descriptor, count - 1);
    write<uint16_t>(offset + stream_format, format);
    address(offset + bdl_base, descriptors);
    return configure_path(channel.path, capture, format, tag);
}

uint32_t position(Direction direction) {
    return read<uint32_t>(stream(direction).offset + link_position);
}

bool failed(Direction direction) {
    return !available(direction) ||
           (read<uint8_t>(stream(direction).offset + stream_status) & stream_errors);
}

void shutdown() {
    disable();
}
} // namespace ax::Hda
