// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <stddef.h>
#include <stdint.h>

enum { WIRE_SCENARIOS = 13, WIRE_CASES = WIRE_SCENARIOS * 6 };

struct WireLink {
    unsigned index;
    unsigned char mac[6];
    int control;
};

struct WireInput {
    uint32_t source, destination;
    uint8_t ttl, tos;
};

extern struct WireLink wire_links[2];
void wire_check(int, const char*);
void wire_hex(const void*, size_t);
void wire_configure(void);
void wire_reopen_control(unsigned lane);
void wire_change_address(unsigned lane, uint32_t address, const char* suffix, int add);
void wire_change_route(uint32_t target, unsigned index, int add);
void wire_change_route_metric(uint32_t target, unsigned index, unsigned metric, int add);
void wire_inventory_paths(unsigned lane, unsigned sequence, unsigned phase, uint32_t target,
                          unsigned expected, unsigned count);
void wire_remove_prefix(unsigned lane);
void wire_inventory_prefix(unsigned lane, unsigned sequence, unsigned phase, uint32_t target,
                           unsigned prefix, unsigned expected, unsigned count);
void wire_inventory(unsigned lane, unsigned sequence, unsigned phase, uint32_t target, int routes,
                    unsigned expected);
void wire_transition(unsigned lane, unsigned sequence, unsigned scenario, unsigned phase);
struct WireInput wire_input(unsigned lane, unsigned sequence, unsigned scenario);

static inline uint32_t wire_primary(unsigned lane) {
    return 0x0a4d0102 + (lane << 8);
}

static inline uint32_t wire_alias(unsigned lane) {
    return wire_primary(lane) + 40;
}

static inline uint32_t wire_prefix(unsigned lane) {
    return 0xc6120102 + (lane << 8);
}

static inline uint32_t wire_group(unsigned lane) {
    return 0xef4d0101 + (lane << 8);
}
