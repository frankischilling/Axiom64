// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/tests/firmware/aml_routing.cpp
 * @brief   Checks AML PCI route evaluation and rejection.
 * @author  frankischilling
 * @date    2026-11-19
 *
 * Constructs definition blocks and exercises the production AML reader and
 * PCI route lookup under host sanitizers.
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
#include "firmware/aml.hpp"
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <initializer_list>
#include <vector>

namespace ax {
void* alloc(size_t n) {
    return std::malloc(n);
}

void release(void* p) {
    std::free(p);
}
} // namespace ax

namespace {
using Bytes = std::vector<uint8_t>;

Bytes sequence(std::initializer_list<Bytes> inputs) {
    Bytes output;
    for (const auto& input : inputs)
        output.insert(output.end(), input.begin(), input.end());
    return output;
}

Bytes name(const char* text) {
    Bytes output;
    for (; *text; ++text)
        output.push_back(uint8_t(*text));
    return output;
}

Bytes block(Bytes opcode, Bytes body) {
    if (body.size() + 1 <= 63) {
        opcode.push_back(uint8_t(body.size() + 1));
    } else {
        unsigned length = unsigned(body.size() + 2);
        assert(length <= 4095);
        opcode.push_back(uint8_t(0x40 | (length & 15)));
        opcode.push_back(uint8_t(length >> 4));
    }
    return sequence({opcode, body});
}

Bytes data(const char* label, Bytes value) {
    return sequence({{0x08}, name(label), value});
}

Bytes package(unsigned count, Bytes children) {
    return block({0x12}, sequence({{uint8_t(count)}, children}));
}

Bytes definition(Bytes body) {
    return sequence({Bytes(36), body});
}

struct Fixture {
    Bytes dsdt, ssdt;
};

Fixture firmware(bool invalid_checksum = false, bool duplicate = false, bool unsupported = false,
                 Bytes children = {}) {
    // A link in a different table from its references. Its interrupt is at resource index 1.
    Bytes resources{
        0x71, 0xaa, 0x89, 6, 0, 9, 1, 45, 0, 0, 0, 0x79, uint8_t(invalid_checksum ? 1 : 0)};
    auto crs =
        data("_CRS", block({0x11}, sequence({{0x0a, uint8_t(resources.size())}, resources})));
    auto link = block({0x5b, 0x82}, sequence({name("LNKA"), crs}));
    auto supplement = definition(block({0x10}, sequence({name("\\_SB_"), link})));

    auto linked_route = package(4, sequence({{0x0c, 0xff, 0xff, 0x04, 0}, {0}, name("LNKA"), {1}}));
    auto direct_route = package(4, {0x0c, 0x02, 0, 0x05, 0, 0x0a, 1, 0, 0x0a, 30});
    auto routes =
        data("RTBL", package(duplicate ? 3 : 2, sequence({linked_route, direct_route,
                                                          duplicate ? linked_route : Bytes{}})));
    auto branch = block({0xa0}, sequence({{0x93}, name("PICF"), {1, 0xa4}, name("^RTBL")}));
    auto other = block({0xa1}, {0xa4, 0});
    auto prt = block({0x14}, sequence({name("_PRT"), {0}, branch, other}));
    auto hid = data("_HID", sequence({{0x0d}, name("PNP0A08"), {0}}));
    // This name shadows the link inside the bridge, but RTBL is declared in the parent.
    auto local = data("LNKA", {0});
    auto bridge = block({0x5b, 0x82}, sequence({name("PCI0"), hid, data("_SEG", {0x0a, 2}),
                                                data("_BBN", {0x0a, 3}), local, prt, children}));
    auto scope = block({0x10}, sequence({name("_SB_"), routes, bridge}));
    Bytes method = unsupported ? Bytes{0x5b, 0x22, 0} : sequence({{0x70, 0x68}, name("PICF")});
    auto pic = block({0x14}, sequence({name("_PIC"), {1}, method}));
    auto main = definition(sequence({data("PICF", {0}), pic, scope}));
    return {main, supplement};
}

bool evaluate(const Fixture& fixture, ax::Acpi::PciPinRoutes& routes, bool with_ssdt = true,
              ax::Acpi::PciBridges* bridges = nullptr, ax::Acpi::PciConfigRead read = nullptr,
              ax::Acpi::PciLinkProgram program = {}) {
    ax::Acpi::DefinitionBlocks blocks{};
    blocks.dsdt = {fixture.dsdt.data(), 0x1000, fixture.dsdt.size()};
    if (with_ssdt) {
        blocks.ssdt[0] = {fixture.ssdt.data(), 0x2000, fixture.ssdt.size()};
        blocks.ssdt_count = 1;
    }
    return ax::Acpi::decode_pci_pin_routes(blocks, routes, bridges, read, program);
}

Bytes bridge_device(const char* label, uint8_t slot, const Bytes& children, uint16_t function = 0) {
    return block({0x5b, 0x82},
                 sequence({name(label),
                           data("_ADR", {0x0c, uint8_t(function), uint8_t(function >> 8), slot, 0}),
                           children}));
}

Bytes bridge_table(uint8_t slot, uint8_t pin, uint8_t gsi) {
    return data("_PRT",
                package(1, package(4, {0x0c, 0xff, 0xff, slot, 0, 0x0a, pin, 0, 0x0a, gsi})));
}

void bridge_cases() {
    using namespace ax::Acpi;
    PciPinRoutes routes{};
    PciBridges bridges{
        {{2, 3, 4, 8, 4, 0, false, false}, {2, 4, 7, 8, 3, 0, false, false}}, 2, false};
    assert(evaluate(firmware(), routes, true, &bridges));
    auto route = find_pci_pin(routes, 2, 7, 1, 0, 1, &bridges);
    assert(route && route->gsi == 45 && route->bus == 3);
    assert(!find_pci_pin(routes, 2, 7, 1, 0, 0, &bridges));
    assert(!find_pci_pin(routes, 3, 7, 1, 0, 1, &bridges));
    assert(!find_pci_pin(routes, 2, 7, 1, 0, 1));

    bridges.entries[0].ari = true;
    route = find_pci_pin(routes, 2, 4, 3, 1, 1, &bridges);
    assert(route && route->gsi == 45);
    bridges.entries[0].ari = false;
    assert(!find_pci_pin(routes, 2, 4, 3, 1, 1, &bridges));

    auto root_child = bridge_device("UPST", 4, bridge_table(3, 1, 61));
    assert(evaluate(firmware(false, false, false, root_child), routes, true, &bridges));
    route = find_pci_pin(routes, 2, 7, 1, 0, 1, &bridges);
    assert(route && route->gsi == 61 && route->bus == 4);

    auto downstream = bridge_device("DOWN", 3, bridge_table(1, 0, 73));
    root_child = bridge_device("UPST", 4, sequence({bridge_table(3, 1, 61), downstream}));
    assert(evaluate(firmware(false, false, false, root_child), routes, true, &bridges));
    route = find_pci_pin(routes, 2, 7, 1, 0, 1, &bridges);
    assert(route && route->gsi == 73 && route->bus == 7);

    downstream = bridge_device("DOWN", 3, data("_PRT", {0}));
    root_child = bridge_device("UPST", 4, sequence({bridge_table(3, 1, 61), downstream}));
    assert(evaluate(firmware(false, false, false, root_child), routes, true, &bridges));
    assert(!find_pci_pin(routes, 2, 7, 1, 0, 1, &bridges));
    assert(find_pci_pin(routes, 2, 3, 4, 0, 1, &bridges));

    bridges.entries[2] = {2, 3, 9, 10, 4, 1, false, false};
    bridges.count = 3;
    auto wildcard = bridge_device("UPST", 4, bridge_table(3, 1, 61), UINT16_MAX);
    assert(evaluate(firmware(false, false, false, wildcard), routes, true, &bridges));
    route = find_pci_pin(routes, 2, 4, 3, 0, 2, &bridges);
    assert(route && route->gsi == 61 && route->bus == 4);
    route = find_pci_pin(routes, 2, 9, 3, 0, 2, &bridges);
    assert(route && route->gsi == 61 && route->bus == 9);
    bridges.count = 2;

    assert(evaluate(firmware(), routes, true, &bridges));
    bridges.entries[0].subordinate = 6;
    assert(!find_pci_pin(routes, 2, 7, 1, 0, 1, &bridges));
    bridges.entries[0].subordinate = 8;
    bridges.entries[2] = {2, 3, 5, 9, 6, 0, false, false};
    bridges.count = 3;
    assert(!find_pci_pin(routes, 2, 7, 1, 0, 1, &bridges));
    bridges.entries[2].secondary = 4;
    assert(!find_pci_pin(routes, 2, 7, 1, 0, 1, &bridges));
    bridges.overflow = true;
    assert(!find_pci_pin(routes, 2, 7, 1, 0, 1, &bridges));
    assert(find_pci_pin(routes, 2, 3, 4, 0, 1, &bridges));
    std::puts("ACPI_PCI_BRIDGE_ROUTING_PASS swizzle ari subordinate_prt wildcard_adr invalid_scope "
              "bus_ranges");
}

enum class DynamicCase { Valid, Disabled, Unbounded, EscapingField, HardwareStore };
unsigned config_reads;
uint8_t link_setting;

bool read_config(uint16_t segment, uint8_t bus, uint8_t slot, uint8_t function, uint16_t offset,
                 uint8_t width, uint32_t& value) {
    ++config_reads;
    if (segment != 2 || bus != 3 || slot != 1 || function || offset != 0x60 || width != 1)
        return false;
    value = link_setting;
    return true;
}

Fixture dynamic_firmware(DynamicCase scenario) {
    // The route method builds two independent rows and sets the slot and pin through Index.
    auto entry = package(4, sequence({{0, 0, 0x2e}, name("PCIBLNKA"), {0}}));
    Bytes address{0x7d, 0x79, 0x72, 0x61, 0x0a, 4, 0, 0x0a, 16, 0, 0x0b, 0xff, 0xff, 0};
    auto iteration =
        sequence({{0x95, 0x61, 0x0a, 2, 0x70},
                  entry,
                  {0x62, 0x70},
                  address,
                  {0x88, 0x62, 0, 0, 0x70, 0x61, 0x88, 0x62, 1, 0, 0x70, 0x62, 0x88, 0x60, 0x61, 0},
                  {0x75, 0x61}});
    // Stall before allocations so the infinite-loop case exercises the instruction limit.
    if (scenario == DynamicCase::Unbounded)
        iteration = Bytes{1};
    auto method = block({0x14}, sequence({name("_PRT"),
                                          {0, 0x70},
                                          package(2, {}),
                                          {0x60, 0x70, 0, 0x61},
                                          block({0xa2}, iteration),
                                          {0xa4, 0x60}}));

    Bytes resources{0x89, 6, 0, 9, 1, 0, 0, 0, 0, 0x79, 0};
    auto buffer =
        data("RBUF", block({0x11}, sequence({{0x0a, uint8_t(resources.size())}, resources})));
    auto create = sequence({{0x8a}, name("RBUF"), {0x0a, 5}, name("IRQN")});
    auto fill = block({0xa0}, sequence({{0x95, 0x68, 0x0a, 0x80, 0x70, 0x68}, name("IRQN")}));
    auto helper =
        block({0x14}, sequence({name("READ"), {1}, buffer, create, fill, {0xa4}, name("RBUF")}));
    auto write =
        scenario == DynamicCase::HardwareStore ? sequence({{0x70, 1}, name("PIN0")}) : Bytes{};
    auto crs =
        block({0x14}, sequence({name("_CRS"), {0}, write, {0xa4}, name("READ"), name("PIN0")}));
    auto link = block({0x5b, 0x82}, sequence({name("LNKA"), crs}));
    auto field = block({0x5b, 0x81}, sequence({name("PIRQ"), {1}, name("PIN0"), {8}}));
    auto region = sequence({{0x5b, 0x80},
                            name("PIRQ"),
                            {2, 0x0a, 0x60, uint8_t(scenario != DynamicCase::EscapingField)}});
    auto pci = bridge_device("PCIB", 1, sequence({region, field, helper, link}));
    auto hid = data("_HID", {0x0c, 0x41, 0xd0, 0x0a, 0x03});
    auto root = block({0x5b, 0x82}, sequence({name("PCI0"), hid, data("_SEG", {0x0a, 2}),
                                              data("_BBN", {0x0a, 3}), pci, method}));
    return {definition(root), {}};
}

void dynamic_cases() {
    using namespace ax::Acpi;
    // Positive and disabled controls share the same valid bytecode and differ only in the PCI read.
    for (auto scenario : {DynamicCase::Valid, DynamicCase::Disabled, DynamicCase::Unbounded,
                          DynamicCase::EscapingField, DynamicCase::HardwareStore}) {
        PciPinRoutes routes{};
        config_reads = 0;
        link_setting = scenario == DynamicCase::Disabled ? 0x8a : 10;
        bool admitted = evaluate(dynamic_firmware(scenario), routes, false, nullptr, read_config);
        if (scenario == DynamicCase::Valid) {
            assert(admitted && routes.count == 2 && config_reads == 2);
            for (uint8_t lane = 0; lane < 2; ++lane) {
                auto* route = find_pci_pin(routes, 2, 3, 4 + lane, 0, 1 + lane);
                assert(route && route->gsi == 10 && route->level && !route->active_low);
            }
        } else {
            assert(!admitted && !routes.count);
            assert(config_reads == (scenario == DynamicCase::Disabled ? 2u : 0u));
        }
    }
    std::puts(
        "ACPI_PCI_DYNAMIC_ROUTING_PASS packages loop_bound pci_region disabled_link read_only");
}

enum class LinkCase { valid, bad_checksum, wrong_field, wrong_status, extra_store, invalid_route };
uint8_t pirq[2];
std::vector<unsigned> link_writes;
bool fail_second_write, fail_rollback;

bool read_pirq(uint16_t segment, uint8_t bus, uint8_t slot, uint8_t function, uint16_t offset,
               uint8_t width, uint32_t& value) {
    if (segment || bus || slot != 1 || function || width != 1 || offset < 0x60 || offset > 0x61)
        return false;
    value = pirq[offset - 0x60];
    return true;
}

bool write_pirq(uint16_t segment, uint8_t bus, uint8_t slot, uint8_t function, uint16_t offset,
                uint8_t previous, uint8_t next) {
    uint32_t current;
    assert(read_pirq(segment, bus, slot, function, offset, 1, current) && current == previous);
    link_writes.push_back(unsigned(offset) << 8 | next);
    if ((offset == 0x61 && fail_second_write) || (next == 0x80 && fail_rollback))
        return false;
    pirq[offset - 0x60] = next;
    return true;
}

Bytes buffer(const char* label, const Bytes& bytes) {
    return data(label, block({0x11}, sequence({{0x0a, uint8_t(bytes.size())}, bytes})));
}

Bytes programmable_link(const char* label, const char* field, LinkCase scenario) {
    auto hid = data("_HID", {0x0c, 0x41, 0xd0, 0x0c, 0x0f});
    auto possible = buffer("_PRS", {0x89, 10, 0, 9, 2, 9, 0, 0, 0, 11, 0, 0, 0, 0x79,
                                    uint8_t(scenario == LinkCase::bad_checksum)});
    auto disabled = block({0xa0}, sequence({{0x7b}, name(field), {0x0a, 0x80, 0, 0xa4, 0x0a, 9}}));
    auto status = block(
        {0x14}, sequence({name("_STA"),
                          {0},
                          disabled,
                          {0xa4, 0x0a, uint8_t(scenario == LinkCase::wrong_status ? 9 : 11)}}));
    auto current = buffer("RBUF", {0x89, 6, 0, 9, 1, 0, 0, 0, 0, 0x79, 0});
    auto crs = block(
        {0x14},
        sequence(
            {name("_CRS"),
             {0},
             current,
             {0x8a},
             name("RBUF"),
             {0x0a, 5},
             name("IRQN"),
             block({0xa0},
                   sequence({{0x95}, name(field), {0x0a, 0x80, 0x70}, name(field), name("IRQN")})),
             {0xa4},
             name("RBUF")}));
    auto extra = scenario == LinkCase::extra_store ? sequence({{0x70, 1}, name("DATA")}) : Bytes{};
    auto srs = block({0x14}, sequence({name("_SRS"),
                                       {1, 0x8a, 0x68, 0x0a, 5},
                                       name("IRQN"),
                                       {0x70},
                                       name("IRQN"),
                                       name(scenario == LinkCase::wrong_field ? "PIN1" : field),
                                       extra}));
    return block({0x5b, 0x82}, sequence({name(label), hid, possible, status, crs, srs}));
}

Fixture programmable_firmware(LinkCase scenario = LinkCase::valid, bool second_link = false) {
    auto registers = sequence(
        {{0x5b, 0x80},
         name("PIRQ"),
         {2, 0x0a, 0x60, 0x0a, 2},
         block({0x5b, 0x81}, sequence({name("PIRQ"), {1}, name("PIN0"), {8}, name("PIN1"), {8}})),
         data("DATA", {0})});
    auto bridge = bridge_device(
        "SBRG", 1,
        sequence({registers, programmable_link("LNKA", "PIN0", scenario),
                  second_link ? programmable_link("LNKB", "PIN1", LinkCase::valid) : Bytes{}}));
    auto first = package(4, sequence({{0x0c, 0xff, 0xff, 4, 0, 0, 0x2e}, name("SBRGLNKA"), {0}}));
    auto second =
        second_link
            ? package(4, sequence({{0x0c, 0xff, 0xff, 5, 0, 0, 0x2e}, name("SBRGLNKB"), {0}}))
            : package(4, sequence({{0x0c, 0xff, 0xff, 5, 0, 0, 0x2e}, name("SBRGLNKA"), {0}}));
    auto direct = scenario == LinkCase::invalid_route
                      ? Bytes{0}
                      : package(4, {0x0c, 0xff, 0xff, 6, 0, 0, 0, 0x0a, 21});
    auto prt = data("_PRT", package(3, sequence({first, second, direct})));
    auto hid = data("_HID", {0x0c, 0x41, 0xd0, 0x0a, 0x03});
    return {definition(block({0x5b, 0x82}, sequence({name("PCI0"), hid, bridge, prt}))), {}};
}

void programmable_cases() {
    using namespace ax::Acpi;
    PciPinRoutes routes{};
    PciLinkProgram program{write_pirq, 1u << 11};
    pirq[0] = pirq[1] = 0x80;
    for (auto scenario : {LinkCase::bad_checksum, LinkCase::wrong_field, LinkCase::wrong_status,
                          LinkCase::extra_store}) {
        assert(
            evaluate(programmable_firmware(scenario), routes, false, nullptr, read_pirq, program));
        assert(routes.count == 1 && !routes.programmed_links && link_writes.empty());
        assert(pirq[0] == 0x80 && pirq[1] == 0x80);
    }
    assert(!evaluate(programmable_firmware(LinkCase::invalid_route), routes, false, nullptr,
                     read_pirq, program));
    assert(link_writes.empty() && !routes.count);
    assert(evaluate(programmable_firmware(), routes, false, nullptr, read_pirq,
                    {write_pirq, 1u << 10}));
    assert(routes.count == 1 && !routes.programmed_links && link_writes.empty());

    assert(evaluate(programmable_firmware(), routes, false, nullptr, read_pirq, program));
    assert(routes.count == 3 && routes.programmed_links == 1 && !routes.rollback_failed);
    assert((link_writes == std::vector<unsigned>{0x600b}));
    for (uint8_t slot : {4, 5}) {
        auto* route = find_pci_pin(routes, 0, 0, slot, 0, 1);
        assert(route && route->gsi == 11 && route->level && route->shared && !route->active_low);
    }
    link_writes.clear();
    assert(evaluate(programmable_firmware(), routes, false, nullptr, read_pirq, program));
    assert(routes.count == 3 && !routes.programmed_links && link_writes.empty());

    fail_second_write = true;
    for (bool rollback_failure : {false, true}) {
        fail_rollback = rollback_failure;
        pirq[0] = pirq[1] = 0x80;
        assert(!evaluate(programmable_firmware(LinkCase::valid, true), routes, false, nullptr,
                         read_pirq, program));
        assert((link_writes == std::vector<unsigned>{0x600b, 0x610b, 0x6080}));
        assert(!routes.count && !routes.programmed_links &&
               routes.rollback_failed == fail_rollback);
        assert(pirq[0] == (fail_rollback ? 11 : 0x80) && pirq[1] == 0x80);
        link_writes.clear();
    }
    std::puts("ACPI_PCI_LINK_PASS disabled shared enabled allowed_irq aml_rejection rollback");
}

void i2c_hid_cases() {
    using namespace ax::Acpi;
    const char* controller = "\\_SB_.PCI0.I2C0";
    const auto source = sequence({name(controller), {0}});
    const uint8_t length = 15 + source.size();
    const auto resources =
        sequence({{0x8e, length, 0, 2, 0, 1, 2, 0, 0, 1, 6, 0, 0x80, 0x1a, 0x06, 0, 0x15, 0},
                  source,
                  {0x79, 0}});
    const Bytes guid{0xf7, 0xf6, 0xdf, 0x3c, 0x67, 0x42, 0x55, 0x45,
                     0xad, 0x05, 0xb3, 0x0a, 0x3d, 0x89, 0x38, 0xde};
    const auto method =
        block({0x14}, sequence({name("_DSM"),
                                {4},
                                block({0xa0}, sequence({{0x93, 0x68},
                                                        block({0x11}, sequence({{0x0a, 16}, guid})),
                                                        {0xa4, 0x0b, 0x22, 0x01}})),
                                {0xa4},
                                block({0x11}, {1, 0})}));
    auto inspect = [&](const Bytes& current, bool present, I2cHidDevices& devices) {
        const auto hid = data("_HID", sequence({{0x0d}, name("ELAN0406"), {0}}));
        const auto cid = data("_CID", package(1, {0x0c, 0x41, 0xd0, 0x0c, 0x50}));
        const auto crs =
            data("_CRS", block({0x11}, sequence({{0x0a, uint8_t(current.size())}, current})));
        const auto table = definition(
            block({0x5b, 0x82}, sequence({name("TPAD"), hid, cid, crs, method,
                                          data("_STA", {0x0a, uint8_t(present ? 15 : 0)})})));
        DefinitionBlocks blocks{};
        blocks.dsdt = {table.data(), 0x1000, table.size()};
        return decode_i2c_hid_devices(blocks, devices);
    };
    I2cHidDevices devices{};
    assert(inspect(resources, true, devices) && devices.count == 1);
    const auto& device = devices.devices[0];
    assert(!std::strcmp(device.hardware_id, "ELAN0406") &&
           !std::strcmp(device.controller, controller) && device.address == 0x15 &&
           device.max_hz == 400000 && !device.ten_bit && device.has_descriptor_register &&
           device.descriptor_register == 0x122);
    assert(inspect(resources, false, devices) && !devices.count);
    auto bad = resources;
    bad[10] = 5; // The I2C type data must include speed and address.
    assert(inspect(bad, true, devices) && !devices.count);
    bad = resources;
    bad[17] = 2; // A seven-bit address cannot use upper address bits.
    assert(inspect(bad, true, devices) && !devices.count);
    bad = resources;
    bad.back() = 1; // Invalid resource-template checksum.
    assert(inspect(bad, true, devices) && !devices.count);
    std::puts("ACPI_I2C_HID_PASS descriptor_register bounded_resource_template");
}

Bytes address_window(uint8_t tag, uint8_t general, uint8_t flags, uint64_t base, uint64_t end,
                     uint64_t size, uint64_t translation = 0, uint64_t attributes = 0) {
    const unsigned width = tag == 0x87 ? 4 : 8;
    const bool extended = tag == 0x8b;
    Bytes bytes{tag, uint8_t(3 + width * 5 + (extended ? 10 : 0)), 0, 0, general, flags};
    if (extended)
        bytes.insert(bytes.end(), {1, 0});
    auto put = [&](uint64_t value, unsigned n) {
        for (unsigned i = 0; i < n; ++i)
            bytes.push_back(uint8_t(value >> (8 * i)));
    };
    for (uint64_t value : {uint64_t(0), base, end, translation, size})
        put(value, width);
    if (extended)
        put(attributes, 8);
    return bytes;
}

void root_window_cases() {
    using namespace ax::Acpi;
    auto inspect = [](const Bytes& resources, bool present, PciRootWindows& windows) {
        const auto hid = data("_HID", {0x0c, 0x41, 0xd0, 0x0a, 0x08});
        const auto status = data("_STA", {0x0a, uint8_t(present ? 15 : 0)});
        const auto dword = data("BASE", {0x0c, 0x00, 0x00, 0x00, 0xfe});
        // A device unrelated to PCI routing can use a computed SystemMemory base.
        const auto region = sequence(
            {{0x5b, 0x80}, name("REG0"), {0, 0x72}, name("BASE"), {0x0a, 0x20, 0, 0x0a, 8}});
        auto root =
            block({0x5b, 0x82}, sequence({name("PCI0"), hid, status, data("_SEG", {0x0a, 2}),
                                          data("_BBN", {0x0a, 64}), buffer("_CRS", resources)}));
        // Constant branches can contain unreachable firmware declarations.
        auto other = block({0xa0}, {0, 0xfe});
        auto alternative = block({0xa1}, root);
        const auto table = definition(sequence({dword, region, other, alternative}));
        DefinitionBlocks blocks{};
        blocks.dsdt = {table.data(), 0x1000, table.size()};
        return decode_pci_root_windows(blocks, windows);
    };

    const auto low = address_window(0x87, 0x0d, 1, 0xfe000000, 0xfe00ffff, 0x10000);
    const auto high = address_window(0x8a, 0x0c, 7, 0x4000000000, 0x401fffffff, 0x20000000);
    const auto consumer = address_window(0x8b, 0x0d, 1, 0x5000000000, 0x5000000fff, 0x1000);
    const auto extended = address_window(0x8b, 0x0c, 1, 0x6000000000, 0x6000000fff, 0x1000, 0, 2);
    const auto translated =
        address_window(0x8a, 0x0c, 1, 0x8000000000, 0x8000000fff, 0x1000, 0x10000);
    auto all = sequence({low, high, consumer, extended, translated, {0x79, 0}});
    PciRootWindows windows{};
    assert(inspect(all, true, windows) && windows.count == 3);
    assert(windows.entries[0].base == 0xfe000000 && windows.entries[0].size == 0x10000 &&
           windows.entries[0].segment == 2 && windows.entries[0].bus == 64 &&
           !windows.entries[0].prefetchable);
    assert(windows.entries[1].base == 0x4000000000 && windows.entries[1].prefetchable);
    assert(windows.entries[2].base == 0x6000000000 && windows.entries[2].prefetchable);
    assert(!inspect(all, false, windows) && !windows.count);
    all.back() = 1;
    assert(!inspect(all, true, windows) && !windows.count);
    auto short_item = high;
    short_item.pop_back();
    assert(!inspect(sequence({low, short_item}), true, windows) && !windows.count);
    const auto bad_range = address_window(0x8a, 0x0c, 1, 0x6000000000, 0x6000000fff, 0x2000);
    assert(!inspect(sequence({low, bad_range, {0x79, 0}}), true, windows) && !windows.count);
    std::puts("ACPI_PCI_ROOT_WINDOWS_PASS fixed_ranges checksum bounds disabled_root");
}
} // namespace

int main() {
    using ax::Acpi::find_pci_pin;
    ax::Acpi::PciPinRoutes routes{};
    auto valid = firmware();
    assert(evaluate(valid, routes) && routes.count == 2);
    auto linked = find_pci_pin(routes, 2, 3, 4, 7, 1);
    assert(linked && linked->gsi == 45 && linked->level && linked->shared && !linked->active_low);
    auto direct = find_pci_pin(routes, 2, 3, 5, 2, 2);
    assert(direct && direct->gsi == 30 && direct->level && direct->shared && direct->active_low);
    assert(!find_pci_pin(routes, 2, 3, 5, 1, 2) && !find_pci_pin(routes, 0, 3, 4, 7, 1));
    assert(!evaluate(valid, routes, false) && !routes.count);
    assert(!evaluate(firmware(true), routes) && !routes.count);
    assert(!evaluate(firmware(false, false, true), routes) && !routes.count);
    assert(evaluate(firmware(false, true), routes) && !find_pci_pin(routes, 2, 3, 4, 7, 1));
    for (size_t size = valid.dsdt.size() - 1; size >= 36; --size) {
        auto truncated = valid;
        truncated.dsdt.resize(size);
        assert(!evaluate(truncated, routes) && !routes.count);
    }
    std::puts("ACPI_PCI_ROUTING_PASS apic_model linked_gsi direct_gsi resource_checksum ambiguity "
              "truncation");
    bridge_cases();
    dynamic_cases();
    programmable_cases();
    i2c_hid_cases();
    root_window_cases();
}
