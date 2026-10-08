// SPDX-License-Identifier: GPL-3.0-or-later
#include <cstdio>
#include <cstdlib>
#include "net/netlink.hpp"

using namespace ax;
static unsigned changes;
static Ipv4Config configurations[3];

static void check(bool condition, const char* reason) {
    if (!condition) {
        std::fprintf(stderr, "ADDRESS_CODEC_FAIL %s\n", reason);
        std::exit(1);
    }
}

namespace ax {
const NetInfo* net_info(unsigned index) {
    static NetInfo information[2];
    return index && index <= 2 ? &information[index - 1] : nullptr;
}

const Ipv4Config* ipv4_config(unsigned index) {
    return index && index <= 2 ? &configurations[index] : nullptr;
}

int ipv4_configure(unsigned index, const Ipv4Config& value) {
    changes++;
    configurations[index] = value;
    return 0;
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
    check(evaluate(fixture) == 0 && changes == 1 && configurations[1].address == 0x0a170128 &&
              configurations[1].mask == 0xffffff00 && configurations[1].broadcast == 0x0a1701ff,
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
    check(evaluate(fixture) == 0 && changes == 2 && !configurations[1].address &&
              configurations[1].mask == 0xffffff00 && !configurations[1].broadcast,
          "exact delete restores the disabled interface's default mask in one call");
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
            bytes[18] |= 1;
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
            bytes[26] = 3;
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
        check(evaluate(bytes) == expected && changes == before && !configurations[1].address,
              "malformed/unsupported message cannot partially alter address state");
    }
    std::puts("ADDRESS_CODEC_FIXTURES_PASS requests=16");
    uint32_t random = 0xa17a5eed;
    for (unsigned trial = 0; trial < 8000; trial++) {
        uint8_t bytes[4096];
        memcpy(bytes, fixture, sizeof(bytes));
        configurations[1] = configurations[2] = {};
        if (trial & 1)
            configurations[1] = {0x0a170128, 0xffffff00, 0x0a1701ff};
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
        Ipv4Config before[3];
        memcpy(before, configurations, sizeof(before));
        unsigned old_changes = changes;
        int result = evaluate(bytes);
        if (result)
            check(changes == old_changes && !memcmp(before, configurations, sizeof(before)),
                  "failed mutated request preserves all backend tuples");
        else
            check(changes == old_changes + 1, "accepted message makes one complete update");
    }
    std::puts("ADDRESS_CODEC_MUTATIONS_PASS count=8000");
}
