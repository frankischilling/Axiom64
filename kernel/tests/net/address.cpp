// SPDX-License-Identifier: GPL-3.0-or-later
#include <cstdio>
#include <cstdlib>
#include "net/netlink.hpp"
#include "net/ipv4/addresses.hpp"

using namespace ax;
static unsigned changes;
static ip4::AddressBook addresses;

static const Ipv4Config& current(unsigned index) {
    auto entry = addresses.preferred(index);
    static const Ipv4Config empty;
    return entry ? entry->config : empty;
}

static bool unchanged(const ip4::AddressBook& before) {
    for (unsigned n = 0; n < ipv4_address_capacity; n++) {
        auto a = before.at(n), b = addresses.at(n);
        if (!a || !b)
            return a == b;
        if (a->index != b->index || a->secondary != b->secondary || strcmp(a->label, b->label) ||
            memcmp(&a->config, &b->config, sizeof(a->config)))
            return false;
    }
    return true;
}

static void check(bool condition, const char* reason) {
    if (!condition) {
        std::fprintf(stderr, "ADDRESS_CODEC_FAIL %s\n", reason);
        std::exit(1);
    }
}

namespace ax {
const NetInfo* net_info(unsigned index) {
    static NetInfo information[2];
    for (unsigned n = 0; n < 2; n++) {
        information[n].index = n + 1;
        std::snprintf(information[n].name, sizeof(information[n].name), "eth%u", n);
    }
    return index && index <= 2 ? &information[index - 1] : nullptr;
}

const Ipv4Address* ipv4_address(unsigned position) {
    return addresses.at(position);
}

int ipv4_address_add(unsigned index, const char* label, const Ipv4Config& value) {
    int error = addresses.add(index, label, value);
    changes += !error;
    return error;
}

int ipv4_address_remove(unsigned index, uint32_t address, uint32_t mask) {
    int error = addresses.remove(index, address, mask);
    changes += !error;
    return error;
}
} // namespace ax

static int evaluate(uint8_t* bytes) {
    NetlinkHeader header;
    memcpy(&header, bytes, sizeof(header));
    return netlink_address_change(bytes, header);
}

int main() {
    uint8_t fixture[4096]{};
    NetlinkHeader header{48, 20, 0x605, 0x12345678, 0x87654321};
    const uint8_t body[]{2, 24, 128, 0, 1, 0, 0, 0};
    const uint8_t attributes[]{8,  0,  2, 0,  10, 23, 1, 40, 8,  0,  1, 0,
                               10, 23, 1, 40, 8,  0,  4, 0,  10, 23, 1, 255};
    memcpy(fixture, &header, sizeof(header));
    memcpy(fixture + 16, body, sizeof(body));
    memcpy(fixture + 24, attributes, sizeof(attributes));
    check(evaluate(fixture) == 0 && changes == 1 && current(1).address == 0x0a170128 &&
              current(1).mask == 0xffffff00 && current(1).broadcast == 0x0a1701ff,
          "independent ifaddrmsg commits complete address/prefix/broadcast in one call");
    check(evaluate(fixture) == -17 && changes == 1, "exclusive create preserves existing address");
    header.type = 21;
    header.flags = 5;
    memcpy(fixture, &header, sizeof(header));
    fixture[17] = 25;
    fixture[47] = 127;
    check(evaluate(fixture) == -99 && changes == 1,
          "delete requires both local address and exact prefix");
    fixture[17] = 24;
    fixture[47] = 255;
    check(evaluate(fixture) == 0 && changes == 2 && !current(1).address &&
              current(1).mask == 0xffffff00 && !current(1).broadcast,
          "exact delete restores the disabled interface's default mask in one call");
    check(addresses.add(1, "eth0", {0x0a170128, 0xffffff00, 0x0a1701ff}) == 0,
          "restore local-only deletion fixture");
    uint8_t local_only[32];
    memcpy(local_only, fixture, sizeof(local_only));
    NetlinkHeader local_header{32, 21, 5, 1, 0};
    memcpy(local_only, &local_header, sizeof(local_header));
    local_only[17] = 0;
    check(evaluate(local_only) == 0 && changes == 3 && !current(1).address,
          "Linux local-only deletion ignores an absent peer prefix");
    uint8_t edge[48];
    memcpy(edge, fixture, sizeof(edge));
    NetlinkHeader edge_header{48, 20, 0x605, 2, 0};
    memcpy(edge, &edge_header, sizeof(edge_header));
    edge[17] = 32;
    edge[31] = edge[39] = 0;
    memset(edge + 44, 0, 4);
    check(evaluate(edge) == 0 && changes == 4, "create a local host address ending in zero");
    edge_header = {32, 21, 5, 3, 0};
    memcpy(edge, &edge_header, sizeof(edge_header));
    edge[17] = 24;
    check(evaluate(edge) == 0 && changes == 5 && !current(1).address,
          "local-only deletion ignores prefix host bits as well as its mask");
    header.type = 20;
    header.flags = 0x605;
    memcpy(fixture, &header, sizeof(header));
    for (unsigned kind = 0; kind < 16; kind++) {
        uint8_t bytes[4096];
        memcpy(bytes, fixture, sizeof(bytes));
        NetlinkHeader invalid = header;
        int expected = -22;
        switch (kind) {
        case 0:
            invalid.length = 23;
            break;
        case 1:
            bytes[16] = 10;
            expected = -97;
            break;
        case 2:
            bytes[17] = 33;
            break;
        case 3:
            bytes[18] |= 2;
            expected = -95;
            break;
        case 4:
            bytes[19] = 253;
            expected = -95;
            break;
        case 5:
            bytes[20] = 3;
            expected = -19;
            break;
        case 6:
            bytes[31] = 41;
            break;
        case 7:
            memcpy(bytes + 48, bytes + 24, 8);
            invalid.length += 8;
            break;
        case 8:
            bytes[26] = 5;
            expected = -95;
            break;
        case 9:
            bytes[24] = 7;
            break;
        case 10:
            invalid.length = 47;
            break;
        case 11:
            memmove(bytes + 24, bytes + 32, 16);
            invalid.length -= 8;
            break;
        case 12:
            bytes[47] = 254;
            break;
        case 13:
            bytes[28] = bytes[36] = 127;
            break;
        case 14:
            bytes[31] = bytes[39] = 0;
            break;
        case 15:
            invalid.flags |= 0x100;
            expected = -95;
            break;
        }
        memcpy(bytes, &invalid, sizeof(invalid));
        unsigned before = changes;
        check(evaluate(bytes) == expected && changes == before && !current(1).address,
              "malformed/unsupported message cannot partially alter address state");
    }
    std::puts("ADDRESS_CODEC_FIXTURES_PASS requests=16");
    uint32_t random = 0xa17a5eed;
    for (unsigned trial = 0; trial < 8000; trial++) {
        uint8_t bytes[4096];
        memcpy(bytes, fixture, sizeof(bytes));
        addresses = {};
        if (trial & 1)
            check(addresses.add(1, "eth0", {0x0a170128, 0xffffff00, 0x0a1701ff}) == 0,
                  "restore mutation fixture");
        for (unsigned i = 0; i < 8; i++) {
            random = random * 1664525 + 1013904223;
            size_t offset = (random >> 8) % (i % 3 ? 48 : sizeof(bytes));
            bytes[offset] ^= uint8_t(random >> 24);
        }
        memcpy(&header, bytes, sizeof(header));
        header.type = trial & 1 ? 21 : 20;
        header.flags = trial & 1 ? 5 : 0x605;
        header.length = trial % 3 ? 48 : 16 + random % (sizeof(bytes) - 15);
        memcpy(bytes, &header, sizeof(header));
        auto before = addresses;
        unsigned old_changes = changes;
        int result = evaluate(bytes);
        if (result)
            check(changes == old_changes && unchanged(before),
                  "failed mutated request preserves all backend tuples");
        else
            check(changes == old_changes + 1, "accepted message makes one complete update");
    }
    std::puts("ADDRESS_CODEC_MUTATIONS_PASS count=8000");
}
