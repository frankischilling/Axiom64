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
#include "drivers/platform/intel_gpio.hpp"
#include "firmware/aml.hpp"
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <initializer_list>
#include <vector>

namespace {
constexpr uint32_t gpio_bases[]{0xfd6e0000, 0xfd6d0000, 0xfd6b0000, 0xfd6a0000};
uint32_t gpio_registers[4][0x10000 / sizeof(uint32_t)];
} // namespace

namespace ax {
void* map_mmio(uint64_t base, size_t length) {
    if (length == sizeof(gpio_registers[0]))
        for (unsigned i = 0; i < 4; ++i)
            if (base == gpio_bases[i])
                return gpio_registers[i];
    return nullptr;
}

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
    auto branch = block({0xa0}, sequence({{0x93}, name("PICF"), {1, 0xa4}, name("^^RTBL")}));
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
    auto entry = package(4, sequence({{0, 0, 0x5e, 0x2e}, name("PCIBLNKA"), {0}}));
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
        const auto pad =
            block({0x5b, 0x82}, sequence({name("TPAD"), hid, cid, crs, method,
                                          data("_STA", {0x0a, uint8_t(present ? 15 : 0)})}));
        const auto bus =
            block({0x5b, 0x82}, sequence({name("I2C0"), data("_ADR", {0x0c, 1, 0, 0x15, 0})}));
        const auto root =
            block({0x5b, 0x82}, sequence({name("PCI0"), data("_HID", {0x0c, 0x41, 0xd0, 0x0a, 8}),
                                          data("_SEG", {1}), data("_BBN", {0x0a, 4}), bus}));
        const auto table =
            definition(sequence({block({0x10}, sequence({name("_SB_"), root})), pad}));
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
    const auto& pci = device.pci_controller;
    assert(pci.resolved && pci.segment == 1 && pci.bus == 4 && pci.slot == 0x15 &&
           pci.function == 1);
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
    std::puts("ACPI_I2C_HID_PASS descriptor_register pci_controller bounded_resource_template");
}

Bytes address_window(uint8_t tag, uint8_t general, uint8_t flags, uint64_t base, uint64_t end,
                     uint64_t size, uint64_t translation = 0, uint64_t attributes = 0) {
    const unsigned width = tag == 0x87 ? 4 : tag == 0x88 ? 2 : 8;
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

void motherboard_resource_cases() {
    using namespace ax::Acpi;
    const Bytes board_id{0x0c, 0x41, 0xd0, 0x0c, 2};
    const Bytes fixed{0x86, 9, 0, 0, 0, 0, 0x24, 0xfd, 0, 0x10, 0, 0};
    const Bytes mem24{0x81, 9, 0, 1, 0, 0xb0, 0x20, 0xb0, 0, 0, 0x10, 0};
    const auto translated =
        address_window(0x8a, 0x0d, 0, 0x4000000000, 0x4000001fff, 0x2000, 0x10000);
    const auto valid = sequence({fixed, mem24, translated, {0x4b, 0xf8, 0x0c, 8, 0x79, 0}});
    const auto other_device = block(
        {0x5b, 0x82}, sequence({name("MEM0"), data("_HID", {0x0c, 0x41, 0xd0, 0x03, 3}),
                                data("_CID", package(1, sequence({{0x0d}, name("PNP0C01"), {0}}))),
                                buffer("_CRS", sequence({fixed, {0x79, 0}}))}));
    auto inspect = [&](const Bytes& resources, const Bytes& status, MotherboardResources& result) {
        auto board =
            block({0x5b, 0x82}, sequence({name("MBRD"), data("_HID", board_id),
                                          data("_STA", status), buffer("_CRS", resources)}));
        const auto table = definition(sequence({other_device, board}));
        DefinitionBlocks blocks{};
        blocks.dsdt = {table.data(), 0x1000, table.size()};
        return decode_motherboard_resources(blocks, result);
    };
    MotherboardResources result{};
    assert(inspect(valid, {1}, result) && result.count == 4 && !result.incomplete);
    const auto& ranges = result.memory;
    assert(ranges[0].base == 0xfd240000 && ranges[0].size == 0x1000);
    assert(ranges[1].base == ranges[0].base && ranges[1].size == ranges[0].size);
    assert(ranges[2].base == 0xb00000 && ranges[2].size == 0x3000);
    assert(ranges[3].base == 0x4000010000 && ranges[3].size == 0x2000);
    assert(inspect(valid, {0}, result) && result.count == 1 && !result.incomplete);
    assert(inspect(valid, {0x0d, 'x', 0}, result) && result.count == 1 && result.incomplete);

    auto bad_checksum = valid;
    bad_checksum.back() = 1;
    assert(inspect(bad_checksum, {1}, result) && result.count == 1 && result.incomplete);
    const auto overflow =
        address_window(0x8a, 0x0d, 0, UINT64_MAX - 0xfff, UINT64_MAX, 0x1000, 0x10000);
    assert(inspect(sequence({fixed, overflow, {0x79, 0}}), {1}, result) && result.count == 1 &&
           result.incomplete);
    const Bytes wrapping32{0x86, 9, 0, 1, 0, 0xf0, 0xff, 0xff, 0, 0x20, 0, 0, 0x79, 0};
    assert(inspect(wrapping32, {1}, result) && result.count == 1 && result.incomplete);

    auto scoped_names = [&](unsigned count) {
        Bytes locals;
        for (unsigned i = 0; i < count; ++i) {
            char local[16];
            std::snprintf(local, sizeof(local), "N%03u", i);
            auto object = data(local, {0});
            locals.insert(locals.end(), object.begin(), object.end());
        }
        const auto nested = block(
            {0x14}, sequence({name("NEST"), {0}, data("N000", {0x0a, 42}), {0xa4}, name("N000")}));
        const auto enabled =
            sequence({{0x90, 0x93}, name("NEST"), {0x0a, 42, 0x93}, name("N000"), {0}});
        const auto resources =
            block({0x14}, sequence({name("_CRS"),
                                    {0},
                                    locals,
                                    block({0xa0}, sequence({enabled, {0xa4}, name("RSRC")})),
                                    {0xa4},
                                    block({0x11}, {0})}));
        auto device =
            block({0x5b, 0x82}, sequence({name("MEM1"), data("_HID", board_id), nested, resources,
                                          buffer("RSRC", sequence({fixed, {0x79, 0}}))}));
        const auto table = definition(sequence({device, other_device}));
        DefinitionBlocks blocks{};
        blocks.dsdt = {table.data(), 0x1000, table.size()};
        return decode_motherboard_resources(blocks, result);
    };
    assert(scoped_names(12) && result.count == 2 && !result.incomplete);
    assert(scoped_names(129) && result.count == 1 && result.incomplete);

    const auto bars = +[](uint64_t address, uint32_t* values, size_t words) {
        if (address != 0xe0000010 || words != 2)
            return false;
        values[0] = 0xfd240004;
        values[1] = 0;
        return true;
    };
    auto inspect_dwords = [&](uint8_t offset, uint8_t length, bool write, PciBarRead read) {
        const auto region =
            sequence({{0x5b, 0x80}, name("RCFG"), {0, 0x0c, offset, 0, 0, 0xe0, 0x0a, length}});
        const auto fields =
            block({0x5b, 0x81}, sequence({name("RCFG"), {3}, name("BAR0"), {0x40, 4}}));
        const auto field = sequence({{0x8a}, name("RSRC"), {0x0a, 4}, name("BASE")});
        const auto change = write ? sequence({{0x70, 0}, name("BAR0")}) : Bytes{};
        const auto crs = block({0x14}, sequence({name("_CRS"),
                                                 {0},
                                                 region,
                                                 fields,
                                                 change,
                                                 buffer("RSRC", sequence({fixed, {0x79, 0}})),
                                                 field,
                                                 {0x7b},
                                                 name("BAR0"),
                                                 {0x0c, 0, 0xf0, 0xff, 0xff},
                                                 name("BASE"),
                                                 {0xa4},
                                                 name("RSRC")}));
        auto table =
            definition(block({0x5b, 0x82}, sequence({name("MBRD"), data("_HID", board_id), crs})));
        table[8] = 2; // This table uses a 64-bit BAR field.
        DefinitionBlocks blocks{};
        blocks.dsdt = {table.data(), 0x1000, table.size()};
        return decode_motherboard_resources(blocks, result, {.pci_bars = read});
    };
    assert(inspect_dwords(0x10, 8, false, bars) && result.count == 1 && !result.incomplete);
    assert(result.memory[0].base == 0xfd240000 && result.memory[0].size == 0x1000);
    assert(inspect_dwords(0x11, 8, false, bars) && !result.count && result.incomplete);
    assert(inspect_dwords(0x10, 7, false, bars) && !result.count && result.incomplete);
    assert(inspect_dwords(0x18, 8, false, bars) && !result.count && result.incomplete);
    assert(inspect_dwords(0x10, 8, true, bars) && !result.count && result.incomplete);
    assert(inspect_dwords(0x10, 8, false, nullptr) && !result.count && result.incomplete);
    std::puts("ACPI_MOTHERBOARD_MEMORY_PASS fixed variable translated inactive partial");
    std::puts("ACPI_MOTHERBOARD_ECAM_PASS words bounds read_only no_provider");
}

unsigned nvs_reads;
bool nvs_lock_seen, nvs_lock_available;

bool read_test_nvs(uint64_t address, uint8_t* bytes, size_t length, bool lock) {
    ++nvs_reads;
    nvs_lock_seen = lock;
    if (address != 0x10000200 || length != 3 || (lock && !nvs_lock_available))
        return false;
    const uint8_t data[]{0xa0, 0x79, 0x01};
    std::memcpy(bytes, data, sizeof(data));
    return true;
}

void nvs_field_cases() {
    using namespace ax::Acpi;
    auto run = [](uint8_t flags, uint8_t length, SystemMemoryRead provider, PciRootWindows& windows,
                  bool large = false) {
        const auto region =
            sequence({{0x5b, 0x80}, name("GNVS"), {0, 0x0c, 0, 2, 0, 0x10, 0x0a, length}});
        const auto fields =
            block({0x5b, 0x81}, sequence({name("GNVS"), {flags, 0, 5}, name("FLAG"), {12}}));
        const auto crs =
            sequence({address_window(0x87, 0x0c, 1, 0xfe000000, 0xfe000fff, 0x1000), {0x79, 0}});
        const auto root =
            block({0x5b, 0x82}, sequence({name("PCI0"), data("_HID", {0x0c, 0x41, 0xd0, 0x0a, 8}),
                                          buffer("_CRS", crs)}));
        const auto predicate =
            sequence({{0x90, 0x93}, name("FLAG"), {0x74, 0x0b, 0xce, 0x0b, 1, 0, 0x91, 0, 1}});
        const auto branch = block({0xa0}, sequence({predicate, root}));
        Bytes extra;
        constexpr char hex[] = "0123456789ABCDEF";
        if (large)
            for (unsigned i = 0; i < 1024; ++i) {
                const char label[]{'Z', hex[i >> 8], hex[(i >> 4) & 15], hex[i & 15], 0};
                auto entry = data(label, {0});
                extra.insert(extra.end(), entry.begin(), entry.end());
            }
        const auto table = definition(sequence({extra, region, fields, branch}));
        DefinitionBlocks blocks{};
        blocks.dsdt = {table.data(), 0x1000, table.size()};
        return decode_pci_root_windows(blocks, windows, {provider});
    };
    PciRootWindows windows{};
    assert(run(0, 3, read_test_nvs, windows) && windows.count == 1 && !nvs_lock_seen);
    assert(nvs_reads == 1 && windows.entries[0].base == 0xfe000000);
    assert(!run(0x10, 3, read_test_nvs, windows) && !windows.count && nvs_lock_seen);
    nvs_lock_available = true;
    assert(run(0x10, 3, read_test_nvs, windows) && windows.count == 1 && nvs_lock_seen);
    assert(nvs_reads == 3);
    assert(!run(0, 2, read_test_nvs, windows) && !windows.count && nvs_reads == 3);
    assert(!run(0, 3, nullptr, windows) && !windows.count && nvs_reads == 3);
    assert(!run(2, 3, read_test_nvs, windows) && !windows.count && nvs_reads == 3);
    assert(run(0, 3, read_test_nvs, windows, true) && windows.count == 1 && nvs_reads == 4);
    std::puts("ACPI_NVS_FIELD_PASS selection cross_byte field_bounds firmware_lock");
}

bool pci_present;
unsigned pci_word_reads;

bool read_pci_words(uint16_t segment, uint8_t bus, uint8_t slot, uint8_t function, uint16_t offset,
                    uint8_t width, uint32_t& out) {
    if (segment || bus || slot != 20 || function != 3 || width != 2 || offset != pci_word_reads * 2)
        return false;
    ++pci_word_reads;
    out = pci_present ? (offset ? 0x1234 : 0x8086) : UINT16_MAX;
    return true;
}

void diagnostic_pci_cases() {
    using namespace ax::Acpi;
    const auto region = sequence({{0x5b, 0x80}, name("CFRG"), {2, 0, 0x0b, 0, 1}});
    const auto field = block({0x5b, 0x81}, sequence({name("CFRG"), {2}, name("VDID"), {32}}));
    const auto endpoint = block(
        {0x5b, 0x82}, sequence({name("DEV0"), data("_ADR", {0x0c, 3, 0, 20, 0}), region, field}));
    const auto check =
        block({0x14}, sequence({name("CNIP"), {0, 0xa4, 0x5e, 0x2e}, name("DEV0"), name("VDID")}));
    const auto root =
        block({0x5b, 0x82},
              sequence({name("PCI0"), data("_HID", {0x0c, 0x41, 0xd0, 0x0a, 8}), endpoint, check}));
    const auto identifier = sequence({{0x5c, 0x2e}, name("PCI0"), name("CNIP")});
    const auto crs =
        sequence({address_window(0x87, 0x0c, 1, 0xfe000000, 0xfe000fff, 0x1000), {0x79, 0}});
    const auto attach = block({0x10}, sequence({name("PCI0"), buffer("_CRS", crs)}));
    const auto branch =
        block({0xa0}, sequence({{0x93}, identifier, {0x0c, 0x86, 0x80, 0x34, 0x12}, attach}));
    const auto table = definition(sequence({root, branch}));
    DefinitionBlocks blocks{};
    blocks.dsdt = {table.data(), 0x1000, table.size()};
    PciRootWindows windows{};
    pci_present = true;
    const ReadRegions providers{read_test_nvs, read_pci_words};
    assert(decode_pci_root_windows(blocks, windows, providers) && windows.count == 1 &&
           pci_word_reads == 2);
    pci_present = false;
    pci_word_reads = 0;
    assert(!decode_pci_root_windows(blocks, windows, providers) && !windows.count &&
           pci_word_reads == 2);
    std::puts("ACPI_DIAGNOSTIC_PCI_PASS word_access parent_scope absent_function");
}

void absent_pci_branch_cases() {
    using namespace ax::Acpi;
    const auto region = sequence({{0x5b, 0x80}, name("CFGR"), {2, 0, 0x0a, 4}});
    const auto fields = block({0x5b, 0x81}, sequence({name("CFGR"), {0}, name("VDID"), {32}}));
    const auto child = bridge_device("END0", 0, sequence({region, fields}));
    const auto bridge = bridge_device("RP01", 28, child);
    const auto root = block(
        {0x5b, 0x82}, sequence({name("PCI0"), data("_HID", {0x0c, 0x41, 0xd0, 0x0a, 8}), bridge}));
    const auto path =
        sequence({{0x5c, 0x2f, 4}, name("PCI0"), name("RP01"), name("END0"), name("VDID")});
    const auto aperture =
        sequence({address_window(0x87, 0x0c, 1, 0xfe000000, 0xfe000fff, 0x1000), {0x79, 0}});
    const auto attach = block({0x10}, sequence({name("PCI0"), buffer("_CRS", aperture)}));
    const auto branch =
        block({0xa0}, sequence({{0x93}, path, {0x0c, 0xff, 0xff, 0xff, 0xff}, attach}));
    const auto table = definition(sequence({root, branch}));
    DefinitionBlocks blocks{};
    blocks.dsdt = {table.data(), 0x1000, table.size()};

    enum Mode { absent, inactive, active, malformed, inaccessible };

    static Mode mode;
    static unsigned attempts;
    const auto read = +[](uint16_t segment, uint8_t bus, uint8_t slot, uint8_t function,
                          uint16_t offset, uint8_t width, uint32_t& value) {
        assert(!segment && !bus && slot == 28 && !function);
        ++attempts;
        if (mode == inaccessible)
            return false;
        if (!offset && width == 2)
            value = mode == absent ? UINT16_MAX : 0x8086;
        else if (offset == 0x0a && width == 2)
            value = 0x0604;
        else if (offset == 0x0e && width == 1)
            value = mode == malformed ? 0 : 1;
        else if (offset == 0x18 && width == 4)
            value = mode == active ? 0x00010100 : 0;
        else
            return false;
        return true;
    };
    PciBridges topology{};
    PciRootWindows windows{};
    const ReadRegions providers{read_test_nvs, read, &topology};
    mode = absent;
    assert(decode_pci_root_windows(blocks, windows, providers) && attempts == 1 &&
           windows.count == 1);
    mode = inactive;
    attempts = 0;
    assert(decode_pci_root_windows(blocks, windows, providers) && attempts == 4 &&
           windows.count == 1);
    for (auto rejected : {active, malformed, inaccessible}) {
        mode = rejected;
        assert(!decode_pci_root_windows(blocks, windows, providers) && !windows.count);
    }
    topology.overflow = true;
    mode = absent;
    attempts = 0;
    assert(!decode_pci_root_windows(blocks, windows, providers) && !attempts);
    std::puts("ACPI_ABSENT_PCI_BRANCH_PASS missing_port disabled_bridge malformed_inaccessible");
}

unsigned host_bridge_reads;

bool read_host_bridge(uint16_t segment, uint8_t bus, uint8_t slot, uint8_t function,
                      uint16_t offset, uint8_t width, uint32_t& value) {
    ++host_bridge_reads;
    if (segment != 2 || bus != 0x40 || slot || function || offset != 0x60 || width != 2)
        return false;
    value = 0xbead;
    return true;
}

void host_bridge_bitfields() {
    using namespace ax::Acpi;
    const auto crs =
        sequence({address_window(0x87, 0x0c, 1, 0xfe000000, 0xfe000fff, 0x1000), {0x79, 0}});
    const auto ready =
        block({0xa0}, sequence({{0x93}, name("PXSZ"), {0x0a, 0x15, 0xa4, 0x0a, 15}}));
    const auto status = block({0x14}, sequence({name("_STA"), {0}, ready, {0xa4, 0}}));
    const auto current = block({0x14}, sequence({name("_CRS"),
                                                 {0, 0x8a},
                                                 name("BUF0"),
                                                 {0x0a, 14},
                                                 name("MAX0"),
                                                 {0x8a},
                                                 name("BUF0"),
                                                 {0x0a, 22},
                                                 name("LEN0"),
                                                 {0x70, 0x0b, 0, 0x20},
                                                 name("LEN0"),
                                                 {0x74, 0x72, 0x0c, 0, 0, 0, 0xfe},
                                                 name("LEN0"),
                                                 {0, 1},
                                                 name("MAX0"),
                                                 {0xa4},
                                                 name("BUF0")}));
    auto inspect = [&](uint8_t length) {
        const auto region = sequence({{0x5b, 0x80}, name("HBUS"), {2, 0x0a, 0x60, 0x0a, length}});
        const auto fields =
            block({0x5b, 0x81}, sequence({name("HBUS"), {2, 0, 3}, name("PXSZ"), {6}}));
        const auto table = definition(
            block({0x5b, 0x82}, sequence({name("PCI0"), data("_HID", {0x0c, 0x41, 0xd0, 0x0a, 8}),
                                          data("_SEG", {0x0a, 2}), data("_BBN", {0x0a, 0x40}),
                                          region, fields, status, buffer("BUF0", crs), current})));
        DefinitionBlocks blocks{};
        blocks.dsdt = {table.data(), 0x1000, table.size()};
        PciRootWindows windows{};
        return decode_pci_root_windows(blocks, windows, {read_test_nvs, read_host_bridge}) &&
               windows.count == 1 && windows.entries[0].segment == 2 &&
               windows.entries[0].bus == 0x40 && windows.entries[0].size == 0x2000;
    };
    assert(inspect(2) && host_bridge_reads == 1);
    assert(!inspect(1) && host_bridge_reads == 1);
    std::puts("ACPI_HOST_BRIDGE_FIELDS_PASS root_function bit_slice access_bounds");
}

void firmware_control_cases() {
    using namespace ax::Acpi;
    auto inspect = [](const Bytes& body) {
        const auto crs =
            sequence({address_window(0x87, 0x0c, 1, 0xfe000000, 0xfe000fff, 0x1000), {0x79, 0}});
        const auto status = block({0x14}, sequence({name("_STA"), {0}, body}));
        const auto root =
            block({0x5b, 0x82}, sequence({name("PCI0"), data("_HID", {0x0c, 0x41, 0xd0, 0x0a, 8}),
                                          buffer("_CRS", crs), status}));
        auto table = definition(
            sequence({data("MARK", {0x0a, 42}),
                      block({0xa0}, sequence({{0x5b, 0x12}, name("NONE"), {0, 0xfe}})),
                      block({0xa0}, sequence({{0x5b, 0x12}, name("MARK"), {0}, root}))}));
        table[8] = 2;
        DefinitionBlocks blocks{};
        blocks.dsdt = {table.data(), 0x1000, table.size()};
        PciRootWindows windows{};
        return decode_pci_root_windows(blocks, windows, {read_test_nvs}) && windows.count == 1;
    };
    const Bytes present{0xa4, 0x0a, 15};
    const auto holds_reference =
        sequence({{0x5b, 0x12},
                  name("MARK"),
                  {0x60, 0x5b, 0x12},
                  name("NONE"),
                  {0x60},
                  block({0xa0}, sequence({{0x93, 0x83, 0x60, 0x0a, 42}, present})),
                  {0xa4, 0}});
    assert(inspect(holds_reference));

    const auto number = block({0x11}, {0x0a, 3, 0x34, 0x12, 0});
    for (const auto& input : {number, sequence({{0x0d}, name(" 0x1234"), {0}}),
                              sequence({{0x0d}, name("4660"), {0}})}) {
        const auto predicate = sequence({{0x93, 0x99}, input, {0, 0x0b, 0x34, 0x12}});
        assert(inspect(sequence({block({0xa0}, sequence({predicate, present})), {0xa4, 0}})));
    }

    const auto loop = block({0xa2}, sequence({{1, 0x75, 0x61},
                                              block({0xa0}, {0x93, 0x61, 1, 0x9f}),
                                              block({0xa0}, {0x93, 0x61, 0x0a, 2, 0xa5}),
                                              {0xa4, 0}}));
    assert(inspect(sequence({{0x70, 0, 0x61}, loop, present})));
    assert(!inspect(sequence({{0xa5}, present})));

    auto nested = present;
    for (unsigned i = 0; i < 20; ++i)
        nested = sequence({block({0xa0}, {0}), block({0xa1}, nested)});
    assert(inspect(nested));
    for (unsigned i = 0; i < 40; ++i)
        nested = sequence({block({0xa0}, {0}), block({0xa1}, nested)});
    assert(!inspect(nested));
    std::puts("ACPI_CONTROL_PROBES_PASS references integer_conversion loop_control depth_limit");
}

void namespace_buffer_fields() {
    using namespace ax::Acpi;
    const auto resource =
        sequence({address_window(0x87, 0x0c, 1, 0xfe000000, 0xfe000fff, 0x1000), {0x79, 0}});
    const auto status =
        block({0x14},
              sequence({name("_STA"),
                        {0},
                        block({0xa0}, sequence({{0x91}, name("WRD0"), name("BIT0"), {0xa4, 0}})),
                        {0x70, 0x0b, 0xa4, 0xa5},
                        name("WRD0"),
                        {0x70, 1},
                        name("BIT0"),
                        block({0xa0},
                              sequence({{0x93}, name("WRD0"), {0x0b, 0xa5, 0xa5, 0xa4, 0x0a, 15}})),
                        {0xa4, 0}}));
    auto inspect = [&](uint8_t offset) {
        const auto word = sequence({{0x8b}, name("BUF0"), {0x0a, offset}, name("WRD0")});
        const auto bit = sequence({{0x8d}, name("BUF0"), {0}, name("BIT0")});
        const auto unrelated_region =
            sequence({{0x5b, 0x80}, name("NVHM"), {0, 0, 0x0c, 0, 4, 3, 0}});
        const auto unrelated_field = block(
            {0x5b, 0x81}, sequence({name("NVHM"), {3, 0, 0x80, 0, 0xf0}, name("OPCE"), {32}}));
        const auto table = definition(block(
            {0x5b, 0x82},
            sequence({name("PCI0"), data("_HID", {0x0c, 0x41, 0xd0, 0x0a, 8}), unrelated_region,
                      unrelated_field, data("BUF0", block({0x11}, {0x0a, 2})), word, bit, status,
                      buffer("_CRS", resource)})));
        DefinitionBlocks blocks{};
        blocks.dsdt = {table.data(), 0x1000, table.size()};
        PciRootWindows windows{};
        return decode_pci_root_windows(blocks, windows, {read_test_nvs}) && windows.count == 1;
    };
    assert(inspect(0));
    assert(!inspect(1));
    std::puts("ACPI_BUFFER_FIELDS_PASS persistent_bytes bounds overlapping_bit");
}

void hid_initialization_cases() {
    using namespace ax::Acpi;
    const char* controller = "\\_SB_.PCI0.I2C0";
    const auto source = sequence({name(controller), {0}});
    const auto serial = sequence({{0x8e, uint8_t(15 + source.size()), 0, 2, 0, 1, 2, 0, 0, 1, 6, 0,
                                   0x80, 0x1a, 0x06, 0, 0, 0},
                                  source,
                                  {0x79, 0}});
    auto method = [](const char* label, const Bytes& body) {
        return block({0x14}, sequence({name(label), {0}, body}));
    };
    const auto region = sequence({{0x5b, 0x80}, name("GNVS"), {0, 0x0b, 0, 2, 0x0a, 2}});
    const auto alias = block({0x5b, 0x81}, sequence({name("GNVS"), {1}, name("WORD"), {16}}));
    const auto seed = method("SEED", sequence({{0x70, 0x0b, 0xaa, 0x02}, name("BITS")}));
    const auto enable = method(
        "_INI",
        block({0xa0}, sequence({{0x93}, name("WORD"), {0x0b, 0x51, 0xd5, 0x70, 1}, name("LIVE")})));
    const auto status = method(
        "_STA", sequence({block({0xa0}, sequence({name("LIVE"), {0xa4, 0x0a, 15}})), {0xa4, 0}}));
    const auto field = sequence({{0x8b}, name("RBUF"), {0x0a, 16}, name("ADDR")});
    const auto rename = sequence({{0x70, 0x0d}, name("ELAN0406"), {0}, name("_HID")});
    const auto leak = sequence({{0x70, 1}, name("LEAK"), {0x5b, 0x22, 0}});
    const auto init = method(
        "_INI",
        block({0xa0}, sequence({{0x92}, name("LEAK"), rename, {0x70, 0x0a, 0x15}, name("ADDR")})));
    auto child = [&](const char* label, const Bytes& sta, const Bytes& ini) {
        return block(
            {0x5b, 0x82},
            sequence({name(label), data("_HID", sequence({{0x0d}, name("XXXX0000"), {0}})),
                      data("_CID", {0x0c, 0x41, 0xd0, 0x0c, 0x50}), sta, buffer("RBUF", serial),
                      field, ini, method("_CRS", sequence({{0xa4}, name("RBUF")}))}));
    };
    static unsigned read_count = 0;
    static bool lock_available = false;
    const auto provider = +[](uint64_t address, uint8_t* bytes, size_t length, bool lock) {
        ++read_count;
        if (address != 0x200 || length != 2 || (lock && !lock_available))
            return false;
        bytes[0] = 0x11;
        bytes[1] = 0x80;
        return true;
    };
    auto read = [&](uint8_t access_flags, uint8_t parent_status, HidDiscovery mode,
                    I2cHidDevices& result) {
        const auto fields =
            block({0x5b, 0x81}, sequence({name("GNVS"), {access_flags, 0, 5}, name("BITS"), {10}}));
        const auto bus =
            bridge_device("I2C0", 21,
                          sequence({data("_STA", {0x0a, parent_status}), data("LIVE", {0}), enable,
                                    child("BAD0", status, method("_INI", leak)),
                                    child("OFF0", data("_STA", {0}), method("_INI", leak)),
                                    child("TPD0", status, init)}));
        const auto root = block(
            {0x5b, 0x82}, sequence({name("PCI0"), data("_HID", {0x0c, 0x41, 0xd0, 0x0a, 8}), bus}));
        const auto system_bus = block({0x10}, sequence({name("_SB_"), root}));
        const auto table = definition(sequence({region, alias, fields, data("LEAK", {0}), seed,
                                                method("_INI", name("SEED")), system_bus}));
        DefinitionBlocks blocks{};
        blocks.dsdt = {table.data(), 0x1000, table.size()};
        return decode_i2c_hid_devices(blocks, result, {provider}, mode);
    };

    I2cHidDevices devices{};
    assert(read(0x11, 0x0f, HidDiscovery::resources, devices) && !devices.count && !read_count);
    assert(read(0x11, 0x0f, HidDiscovery::replay_initialization, devices) && !devices.count &&
           devices.initialization_failures == 3);
    lock_available = true;
    assert(read(0x11, 0x0f, HidDiscovery::replay_initialization, devices) && devices.count == 1 &&
           devices.initialization_failures == 1);
    const auto& device = devices.devices[0];
    assert(!std::strcmp(device.hardware_id, "ELAN0406") && device.address == 0x15 &&
           device.max_hz == 400000 && device.pci_controller.resolved &&
           device.pci_controller.slot == 21);
    assert(read(0x11, 0, HidDiscovery::replay_initialization, devices) && !devices.count &&
           !devices.initialization_failures);
    assert(read(0x31, 0x0f, HidDiscovery::replay_initialization, devices) && !devices.count &&
           devices.initialization_failures == 3);
    std::puts("ACPI_HID_INIT_PASS parent_status helper_call nvs_overlay firmware_lock "
              "candidate_isolation");
}

void aml_integer_match_cases() {
    using namespace ax::Acpi;
    const Bytes serial{0x8e, 19,   0, 2, 0,    1, 2,   0,   0,   1, 6,    0,
                       0x80, 0x1a, 6, 0, 0x15, 0, 'I', '2', 'C', 0, 0x79, 0};
    auto present = [&](Bytes comparison, Bytes expected, unsigned revision = 2) {
        const auto match = sequence({{0x89}, package(4, {1, 0x0a, 5, 1}), comparison});
        const auto sta = block({0x14}, sequence({name("_STA"), {0, 0xa4, 0x93}, match, expected}));
        auto table = definition(block(
            {0x5b, 0x82}, sequence({name("TPAD"), data("_HID", {0x0c, 0x41, 0xd0, 0x0c, 0x50}), sta,
                                    buffer("_CRS", serial)})));
        table[8] = revision;
        DefinitionBlocks blocks{};
        blocks.dsdt = {table.data(), 0x1000, table.size()};
        I2cHidDevices devices{};
        return decode_i2c_hid_devices(blocks, devices) && devices.count == 1;
    };
    assert(present({1, 1, 0, 0, 0}, {0}));             // First equality match.
    assert(present({1, 1, 0, 0, 1}, {0x0a, 2}));       // Start after the first match.
    assert(present({4, 0x0a, 5, 2, 0x0a, 5, 0}, {1})); // Inclusive range includes 5.
    assert(present({5, 1, 3, 0x0a, 5, 0}, {0xff}));    // Strict range excludes both ends.
    assert(present({1, 0x0a, 7, 0, 0, 0}, {0xff}, 1)); // AML v1 uses 32-bit Ones.
    assert(present({0, 0, 0, 0, 0x0a, 3}, {0xff}));    // Uninitialized entry is skipped.
    assert(!present({0, 0, 0, 0, 0x0a, 4}, {0xff}));   // Start outside the package.
    assert(!present({6, 1, 0, 0, 0}, {0}));            // Invalid comparison opcode.
    std::puts("ACPI_AML_MATCH_PASS operators start uninitialized integer_width malformed");
}

void aml_pci_config_replay_cases() {
    using namespace ax::Acpi;
    const auto read_config = +[](uint64_t address, unsigned bytes, uint32_t& value) {
        if (bytes == 2 && (address == 0xe00000d8 || address == 0xe00000da))
            value = address == 0xe00000d8 ? 0xa5a5 : 0x5a5a;
        else if (bytes == 4 && (address == 0xe0000548 || address == 0xe0000ffc))
            value = 0xa5a5a5a5;
        else if (bytes == 4 && (address == 0xe000054c || address == 0xe0001000))
            value = 0x5a5a5a5a;
        else
            return false;
        return true;
    };
    const Bytes serial{0x8e, 19,   0, 2, 0,    1, 2,   0,   0,   1, 6,    0,
                       0x80, 0x1a, 6, 0, 0x15, 0, 'I', '2', 'C', 0, 0x79, 0};
    auto inspect = [&](uint16_t start, uint8_t length, Bytes target, uint8_t event,
                       PciEcamRead provider, bool dword = false) {
        const uint8_t access = dword ? 3 : 2;
        const uint8_t offset = dword ? 30 : 14;
        const uint8_t bits = dword ? 64 : 32;
        const Bytes expected = dword ? Bytes{0x0e, 0xa5, 0xa5, 0xa5, 0x65, 0x59, 0x5a, 0x5a, 0x5a}
                                     : Bytes{0x0c, 0xa5, 0x65, 0x59, 0x5a};
        const auto region =
            sequence({{0x5b, 0x80},
                      name("ECFG"),
                      {0, 0x0c, uint8_t(start), uint8_t(start >> 8), 0, 0xe0, 0x0a, length}});
        const auto fields =
            block({0x5b, 0x81}, sequence({name("ECFG"), {access, 0, offset}, name("BITS"), {4}}));
        const auto width = bits == 64 ? Bytes{0x40, 4} : Bytes{bits};
        const auto full =
            block({0x5b, 0x81}, sequence({name("ECFG"), {access}, name("FULL"), width}));
        const auto record = block(
            {0xa0}, sequence({{0x93}, name("BITS"), {0x0a, 10, 0x70, 0x0a, 5}, name("BITS")}));
        const Bytes arithmetic{0x70, 0, 0x60, 0x76, 0x60, 0x80, 0x60, 0x61};
        const auto activated =
            block({0xa0}, sequence({{0x90, 0x93, 0x60, 0xff, 0x90, 0x93, 0x61, 0, 0x93},
                                    name("FULL"),
                                    expected,
                                    {0x70, 1},
                                    name("LIVE")}));
        const auto ini = block({0x14}, sequence({name("_INI"),
                                                 {0},
                                                 region,
                                                 fields,
                                                 full,
                                                 record,
                                                 {0x86},
                                                 target,
                                                 {0x0a, event},
                                                 arithmetic,
                                                 activated}));
        const auto sta =
            block({0x14}, sequence({name("_STA"), {0, 0xa4, 0x7d}, name("LIVE"), {0x0a, 8, 0}}));
        // The initializer belongs to the parent, whose initial _STA has its present bit set.
        const auto pad = block({0x5b, 0x82},
                               sequence({name("TPAD"), data("_HID", {0x0c, 0x41, 0xd0, 0x0c, 0x50}),
                                         sta, buffer("_CRS", serial)}));
        auto table =
            definition(block({0x5b, 0x82}, sequence({name("PCI0"), data("LIVE", {0}), ini, pad})));
        table[8] = 2;
        DefinitionBlocks blocks{};
        blocks.dsdt = {table.data(), 0x1000, table.size()};
        I2cHidDevices devices{};
        assert(decode_i2c_hid_devices(blocks, devices, {.pci_ecam = provider}));
        assert(!devices.count);
        assert(decode_i2c_hid_devices(blocks, devices, {.pci_ecam = provider},
                                      HidDiscovery::replay_initialization));
        return devices;
    };
    const Bytes parent_name{0x5e, 0};
    assert(inspect(0xd8, 4, parent_name, 0, read_config).count == 1);
    assert(inspect(0xd8, 4, parent_name, 2, read_config).count == 1);
    assert(inspect(0xd9, 4, parent_name, 0, read_config).initialization_failures == 1);
    assert(inspect(0xd8, 3, parent_name, 0, read_config).initialization_failures == 1);
    assert(inspect(0xd6, 4, parent_name, 0, read_config).initialization_failures == 1);
    assert(inspect(0xd8, 4, parent_name, 3, read_config).initialization_failures == 1);
    assert(inspect(0xd8, 4, name("LIVE"), 0, read_config).initialization_failures == 1);
    assert(inspect(0xd8, 4, parent_name, 0, nullptr).initialization_failures == 1);
    assert(inspect(0x548, 8, parent_name, 0, read_config, true).count == 1);
    assert(inspect(0x548, 7, parent_name, 0, read_config, true).initialization_failures == 1);
    assert(inspect(0x549, 8, parent_name, 0, read_config, true).initialization_failures == 1);
    assert(inspect(0xffc, 8, parent_name, 0, read_config, true).initialization_failures == 1);
    std::puts("ACPI_AML_ECAM_PASS width16 width32 alignment bounds notify shadow_writes");
}

void aml_sync_replay_cases() {
    using namespace ax::Acpi;
    const Bytes serial{0x8e, 19,   0, 2, 0,    1, 2,   0,   0,   1, 6,    0,
                       0x80, 0x1a, 6, 0, 0x15, 0, 'I', '2', 'C', 0, 0x79, 0};
    auto sync = [](uint8_t opcode, const char* target, const Bytes& operand = {}) {
        return sequence({{0x5b, opcode}, name(target), operand});
    };
    const auto acquire = sync(0x23, "MTXA", {0xff, 0xff});
    const auto release = sync(0x27, "MTXA");
    const auto signal = sync(0x24, "EVNT");
    const auto poll = sync(0x25, "EVNT", {0});
    const auto reset = sync(0x26, "EVNT");
    const auto enable_if = [](const Bytes& condition) {
        return block({0xa0}, sequence({condition, {0x70, 1}, name("LIVE")}));
    };
    const auto helper = block({0x14}, sequence({name("HELP"), {0}, release, signal}));
    auto inspect = [&](const Bytes& body, uint8_t flags = 0, uint8_t level = 1) {
        const auto init = block({0x14}, sequence({name("_INI"), {flags}, body}));
        const auto sta =
            block({0x14}, sequence({name("_STA"), {0, 0xa4, 0x7d}, name("LIVE"), {0x0a, 8, 0}}));
        const auto pad = block({0x5b, 0x82},
                               sequence({name("TPAD"), data("_HID", {0x0c, 0x41, 0xd0, 0x0c, 0x50}),
                                         sta, buffer("_CRS", serial)}));
        const auto table = definition(block(
            {0x5b, 0x82}, sequence({name("PCI0"), data("LIVE", {0}), sync(1, "MTXA", {level}),
                                    sync(1, "MTXB", {1}), sync(2, "EVNT"), helper, init, pad})));
        DefinitionBlocks blocks{};
        blocks.dsdt = {table.data(), 0x1000, table.size()};
        I2cHidDevices devices{};
        const bool loaded =
            decode_i2c_hid_devices(blocks, devices, {}, HidDiscovery::replay_initialization);
        return loaded ? (devices.initialization_failures ? -1 : int(devices.count)) : -2;
    };
    assert(inspect(sequence(
               {acquire, acquire, sync(0x23, "MTXB", {0, 0}), name("HELP"), release,
                sync(0x27, "MTXB"), signal,
                enable_if(sequence({{0x90, 0x92}, poll, {0x90, 0x92}, poll, poll}))})) == 1);
    assert(inspect(sequence({signal, signal, reset, enable_if(poll)})) == 1);
    assert(inspect(sequence({acquire, release, enable_if({1})}), 0x18) == 1);
    assert(inspect(sequence({acquire, release, enable_if({1})}), 0x28) == -1);
    assert(inspect(sequence({acquire, release, enable_if({1})}), 0, 16) == -2);
    assert(inspect(sequence({acquire, enable_if({1})})) == -1);
    assert(inspect(release) == -1);
    assert(inspect(sync(0x23, "MTXA", {0xff})) == -1);
    assert(inspect(sync(0x24, "MTXA")) == -1);
    assert(inspect(sync(0x25, "EVNT", {1})) == -1);
    assert(inspect(sync(0x23, "\\_GL", {0xff, 0xff})) == -1);
    std::puts("ACPI_AML_SYNC_PASS recursive acquire release levels event_count reset timeout");
}

void intel_gpio_replay_cases() {
    using namespace ax::Acpi;
    using Model = IntelGpioResources::Model;
    auto named_method = [](const char* label, const Bytes& body) {
        return block({0x14}, sequence({name(label), {0}, body}));
    };
    auto read_gpio = [](unsigned index) {
        const uint32_t address = gpio_bases[0] + 0x604 + 16 * index;
        const Bytes base{0x0c, uint8_t(address), uint8_t(address >> 8), uint8_t(address >> 16),
                         uint8_t(address >> 24)};
        const auto region = sequence({{0x5b, 0x80}, name("PREG"), {0, 0x60, 0x0a, 4}});
        const auto fields = block({0x5b, 0x81}, sequence({name("PREG"), {0}, name("PADW"), {32}}));
        const auto declaration = sequence({{0x70}, base, {0x60}, region, fields});
        // A temporary Field exists only during this invocation.
        return block({0x14}, sequence({name("RDGP"),
                                       {0},
                                       declaration,
                                       {0x70, 0x0a, 0x15},
                                       name("PADW"),
                                       {0xa4, 0x7b},
                                       name("PADW"),
                                       {0x0a, 0x7f, 0}}));
    };
    const auto enabled = block({0xa0}, sequence({{0x90, 0x5b, 0x12},
                                                 name("\\_OSI"),
                                                 {0},
                                                 name("\\_OSI"),
                                                 {0x0d},
                                                 name("Windows 2015"),
                                                 {0},
                                                 {0x70, 1},
                                                 name("LIVE")}));
    const auto status = named_method("_STA", sequence({{0xa4}, name("LIVE")}));
    const char* controller = "\\_SB_.PCI0.I2C0";
    const auto source = sequence({name(controller), {0}});
    const auto serial = sequence({{0x8e, uint8_t(15 + source.size()), 0, 2, 0, 1, 2, 0, 0, 1, 6, 0,
                                   0x80, 0x1a, 0x06, 0, 0, 0},
                                  source,
                                  {0x79, 0}});
    const auto field = sequence({{0x8b}, name("RBUF"), {0x0a, 16}, name("ADDR")});
    const auto init = named_method("_INI", sequence({{0x70}, name("RDGP"), name("ADDR")}));
    const auto pad =
        block({0x5b, 0x82},
              sequence({name("TPAD"), data("_HID", sequence({{0x0d}, name("PNP0C50"), {0}})),
                        status, buffer("RBUF", serial), field, init,
                        named_method("_CRS", sequence({{0xa4}, name("RBUF")}))}));

    auto table = [&](bool low_power, bool wrong_address, unsigned pad_index) {
        Bytes windows;
        for (unsigned i = 0; i < 4; ++i) {
            if (low_power && i == 2)
                continue;
            uint32_t base = gpio_bases[i] + (wrong_address && !i ? 0x10000 : 0);
            const Bytes memory{0x86,
                               9,
                               0,
                               1,
                               uint8_t(base),
                               uint8_t(base >> 8),
                               uint8_t(base >> 16),
                               uint8_t(base >> 24),
                               0,
                               0,
                               1,
                               0};
            windows.insert(windows.end(), memory.begin(), memory.end());
        }
        windows = sequence({windows, {0x79, 0}});
        const auto gpio =
            block({0x5b, 0x82},
                  sequence({name("GPI0"),
                            data("_HID",
                                 sequence({{0x0d}, name(low_power ? "INT34BB" : "INT3450"), {0}})),
                            buffer("_CRS", windows)}));
        const auto bus = bridge_device("I2C0", 21,
                                       sequence({data("LIVE", {0}), named_method("_INI", enabled),
                                                 read_gpio(pad_index), pad}));
        const auto root =
            block({0x5b, 0x82},
                  sequence({name("PCI0"), data("_HID", {0x0c, 0x41, 0xd0, 0x0a, 8}), bus, gpio}));
        return definition(block({0x10}, sequence({name("_SB_"), root})));
    };

    const auto no_nvs = +[](uint64_t, uint8_t*, size_t, bool) { return false; };
    for (bool low_power : {false, true}) {
        for (auto& registers : gpio_registers) {
            registers[0] = 0x00920000;
            registers[0x0c / 4] = 0x600;
        }
        gpio_registers[0][0x604 / 4] = 0x45;
        const auto aml = table(low_power, false, 0);
        DefinitionBlocks blocks{};
        blocks.dsdt = {aml.data(), 0x1000, aml.size()};
        IntelGpioResources gpio{};
        assert(decode_intel_gpio_resources(blocks, gpio, {no_nvs}));
        assert(gpio.model == (low_power ? Model::cannon_lake_lp : Model::cannon_lake_h));
        assert(gpio.community_base[2] == gpio_bases[low_power ? 3 : 2]);
        ax::IntelGpioPads pads{};
        assert(pads.probe(gpio));
        uint8_t bytes[4]{};
        assert(!pads.read(&pads, gpio_bases[0] + 0x0c, bytes, 4));
        assert(!pads.read(&pads, gpio_bases[0] + 0x608, bytes, 4));
        assert(!pads.read(&pads, gpio_bases[0] + 0x607, bytes, 2));
        assert(!pads.read(&pads, gpio_bases[0] + 0x604 + (low_power ? 68 : 51) * 16, bytes, 4));
        assert(pads.read(&pads, gpio_bases[0] + 0x604, bytes, 4) && bytes[0] == 0x45);

        I2cHidDevices devices{};
        const ReadRegions regions{no_nvs,    nullptr, nullptr,
                                  pads.read, &pads,   ax::intel_gpio_firmware_interface};
        assert(decode_i2c_hid_devices(blocks, devices, regions) && !devices.count);
        assert(
            decode_i2c_hid_devices(blocks, devices, regions, HidDiscovery::replay_initialization));
        assert(devices.count == 1 && devices.devices[0].address == 0x15 &&
               !devices.initialization_failures && gpio_registers[0][0x604 / 4] == 0x45);

        const auto out_of_range = table(low_power, false, low_power ? 68 : 51);
        blocks.dsdt = {out_of_range.data(), 0x1000, out_of_range.size()};
        assert(
            decode_i2c_hid_devices(blocks, devices, regions, HidDiscovery::replay_initialization));
        assert(!devices.count && devices.initialization_failures == 1);
        const auto wrong = table(low_power, true, 0);
        blocks.dsdt = {wrong.data(), 0x1000, wrong.size()};
        assert(!decode_intel_gpio_resources(blocks, gpio, {no_nvs}) && gpio.model == Model::none);

        blocks.dsdt = {aml.data(), 0x1000, aml.size()};
        assert(decode_intel_gpio_resources(blocks, gpio, {no_nvs}));
        gpio_registers[3][0x0c / 4] = 0xfffffff0;
        assert(!pads.probe(gpio) && !pads.read(&pads, gpio_bases[0] + 0x604, bytes, 4));
    }
    std::puts(
        "ACPI_INTEL_GPIO_PASS communities pad_bounds local_fields interface_probe private_writes");
}

void composed_i2c_resources() {
    using namespace ax::Acpi;
    using Polarity = I2cHidInterrupt::Polarity;
    using Source = I2cHidInterrupt::Source;
    const char* controller = "\\_SB_.PCI0.I2C0";
    const auto source = sequence({name(controller), {0}});
    const auto serial = sequence(
        {{0x8e, uint8_t(15 + source.size()), 0, 2, 0, 1, 2, 0, 0, 1, 6, 0, 0, 0, 0, 0, 0, 0},
         source,
         {0x79, 0}});
    const auto build = block({0x14}, sequence({name("BLDR"),
                                               {0},
                                               buffer("IIC0", serial),
                                               {0x8a},
                                               name("IIC0"),
                                               {0x0a, 12},
                                               name("SPD0"),
                                               {0x8b},
                                               name("IIC0"),
                                               {0x0a, 16},
                                               name("ADR0"),
                                               {0x8d},
                                               name("IIC0"),
                                               {0x0a, 128},
                                               name("BIT0"),
                                               {0x70, 0x0c, 0x80, 0x1a, 0x06, 0},
                                               name("SPD0"),
                                               {0x70, 0x0a, 0x14},
                                               name("ADR0"),
                                               {0x70, 1},
                                               name("BIT0"),
                                               {0xa4},
                                               name("IIC0")}));
    const auto method =
        block({0x14},
              sequence({name("_CRS"), {0, 0x84}, name("BLDR"), name("IRQ0"), {0x61, 0xa4, 0x61}}));
    auto inspect = [&](const Bytes& irq, I2cHidDevices& devices) {
        const auto table = definition(sequence(
            {build,
             block({0x5b, 0x82},
                   sequence({name("TPD0"), data("_HID", sequence({{0x0d}, name("ELAN0406"), {0}})),
                             data("_CID", {0x0c, 0x41, 0xd0, 0x0c, 0x50}), buffer("IRQ0", irq),
                             method}))}));
        DefinitionBlocks blocks{};
        blocks.dsdt = {table.data(), 0x1000, table.size()};
        return decode_i2c_hid_devices(blocks, devices);
    };
    const Bytes irq{0x89, 6, 0, 0x1d, 1, 45, 0, 0, 0, 0x79, 0};
    I2cHidDevices devices{};
    const auto& interrupt = devices.devices[0].interrupt;
    assert(inspect(irq, devices) && devices.count == 1);
    assert(devices.devices[0].address == 0x15 && devices.devices[0].max_hz == 400000 &&
           !std::strcmp(devices.devices[0].controller, controller));
    assert(interrupt.source == Source::gsi && interrupt.line == 45 && !interrupt.edge &&
           interrupt.polarity == Polarity::active_low && interrupt.shared && interrupt.wake);
    assert(inspect({}, devices) && devices.count == 1 && interrupt.source == Source::none);

    const char* gpio_controller = "\\_SB.PCI0.GPI0";
    const auto gpio_path = sequence({name(gpio_controller), {0}});
    const auto gpio = sequence({{0x8c, uint8_t(22 + gpio_path.size()),
                                 0,    1,
                                 0,    1,
                                 0,    0x1a,
                                 0,    1,
                                 0,    0,
                                 0x34, 0x12,
                                 23,   0,
                                 0,    25,
                                 0,    uint8_t(25 + gpio_path.size()),
                                 0,    0,
                                 0,    75,
                                 0},
                                gpio_path,
                                {0x79, 0}});
    assert(inspect(gpio, devices) && devices.count == 1 && interrupt.source == Source::gpio &&
           interrupt.line == 75 && !interrupt.edge && interrupt.polarity == Polarity::active_low &&
           interrupt.shared && interrupt.wake && interrupt.gpio_debounce == 0x1234 &&
           interrupt.gpio_pull == 1 && !std::strcmp(interrupt.gpio_controller, gpio_controller));
    const Bytes gpio_without_end(gpio.begin(), gpio.end() - 2);
    assert(inspect(sequence({gpio_without_end, irq}), devices) && devices.count == 1 &&
           interrupt.source == Source::gsi && interrupt.line == 45 &&
           !interrupt.gpio_controller[0]);
    assert(inspect({0x22, 0, 0x10, 0x79, 0}, devices) && devices.count == 1 &&
           interrupt.source == Source::legacy_irq && interrupt.line == 12 && interrupt.edge &&
           interrupt.polarity == Polarity::active_high && !interrupt.wake);
    auto invalid_gpio = gpio;
    invalid_gpio[19] = 0xff;
    assert(inspect(invalid_gpio, devices) && devices.count == 1 &&
           interrupt.source == Source::none);
    invalid_gpio = gpio;
    invalid_gpio[7] = 4;
    assert(inspect(invalid_gpio, devices) && devices.count == 1 &&
           interrupt.source == Source::none);
    invalid_gpio[7] = 5;
    assert(inspect(invalid_gpio, devices) && devices.count == 1 &&
           interrupt.source == Source::gpio && interrupt.edge &&
           interrupt.polarity == Polarity::both_edges);
    invalid_gpio = gpio;
    invalid_gpio[23] = invalid_gpio[24] = 0xff;
    assert(inspect(invalid_gpio, devices) && devices.count == 1 &&
           interrupt.source == Source::none);
    const Bytes named_irq{0x89, 12, 0, 1, 1, 42, 0, 0, 0, 0, 'I', 'R', 'Q', 'C', 0, 0x79, 0};
    assert(inspect(sequence({gpio_without_end, named_irq}), devices) && devices.count == 1 &&
           interrupt.source == Source::gpio && interrupt.line == 75);
    std::puts("ACPI_I2C_INTERRUPT_PASS gsi isa gpio fallback malformed");

    assert(inspect(sequence({irq, {0, 0}}), devices) && devices.count == 1);
    assert(inspect(sequence({irq, {1}}), devices) && !devices.count);
    assert(inspect(Bytes(irq.begin(), irq.end() - 2), devices) && !devices.count);
    auto invalid_checksum = irq;
    invalid_checksum.back() = 1;
    assert(inspect(invalid_checksum, devices) && !devices.count);
    std::puts("ACPI_I2C_COMPOSED_CRS_PASS mutable_fields serial_bus checksum malformed_end");
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
    motherboard_resource_cases();
    nvs_field_cases();
    diagnostic_pci_cases();
    absent_pci_branch_cases();
    host_bridge_bitfields();
    firmware_control_cases();
    namespace_buffer_fields();
    composed_i2c_resources();
    hid_initialization_cases();
    aml_integer_match_cases();
    aml_pci_config_replay_cases();
    aml_sync_replay_cases();
    intel_gpio_replay_cases();
}
