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
              ax::Acpi::PciBridges* bridges = nullptr, ax::Acpi::PciConfigRead read = nullptr) {
    ax::Acpi::DefinitionBlocks blocks{};
    blocks.dsdt = {fixture.dsdt.data(), 0x1000, fixture.dsdt.size()};
    if (with_ssdt) {
        blocks.ssdt[0] = {fixture.ssdt.data(), 0x2000, fixture.ssdt.size()};
        blocks.ssdt_count = 1;
    }
    return ax::Acpi::decode_pci_pin_routes(blocks, routes, bridges, read);
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
        iteration = {1};
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
}
