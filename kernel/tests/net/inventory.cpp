// SPDX-License-Identifier: GPL-3.0-or-later
#include <cstdio>
#include <cstdlib>
#include <initializer_list>
#include "net/netlink.hpp"

using namespace ax;

static void require(bool condition, const char* operation) {
    if (!condition) {
        std::fprintf(stderr, "NETLINK_INVENTORY_CODEC_FAIL %s\n", operation);
        std::exit(1);
    }
}

namespace ax {
const NetInfo* net_info(unsigned index) {
    static NetInfo information[max_net_devices];
    if (!index || index > max_net_devices)
        return nullptr;
    auto& value = information[index - 1];
    value.index = index;
    std::snprintf(value.name, sizeof(value.name), "eth%u", index - 1);
    memset(value.mac, uint8_t(index), sizeof(value.mac));
    value.administrative = index % 2;
    value.carrier = value.live = index % 3;
    return &value;
}

const Ipv4Config* ipv4_config(unsigned index) {
    static Ipv4Config value;
    value = index == ipv4_loopback
                ? Ipv4Config{0x7f000001, 0xff000000, 0}
                : Ipv4Config{0x0a000002 + (index << 8), 0xffffff00, 0x0a0000ff + (index << 8)};
    return &value;
}
} // namespace ax

static int evaluate(const uint8_t* packet, bool strict, unsigned* records = nullptr) {
    uint8_t output[netlink_max_reply + 16];
    memset(output, 0xa5, sizeof(output));
    NetlinkHeader request;
    memcpy(&request, packet, sizeof(request));
    size_t size = 0;
    int error = netlink_inventory_reply(packet, request, 123, output, strict, size);
    require(size <= netlink_max_reply, "bounded reply size");
    for (size_t i = netlink_max_reply; i < sizeof(output); i++)
        require(output[i] == 0xa5, "reply allocation canary");
    if (error) {
        require(!size, "failed parser preserves caller size");
        for (size_t i = 0; i < netlink_max_reply; i++)
            require(output[i] == 0xa5, "malformed input never publishes a partial reply");
        return error;
    }
    unsigned count = 0;
    for (size_t at = 0; at < size;) {
        NetlinkHeader header;
        require(size - at >= sizeof(header), "complete multipart header");
        memcpy(&header, output + at, sizeof(header));
        require(header.length >= sizeof(header) && header.length <= size - at &&
                    !(header.length % 4) && header.flags == 2 &&
                    header.sequence == request.sequence && header.port == 123,
                "bounded aligned multipart ownership");
        if (header.type == 3) {
            int status;
            memcpy(&status, output + at + sizeof(header), sizeof(status));
            require(header.length == 20 && at + header.length == size && !status,
                    "terminal completion and status");
        } else {
            require(header.type == (request.type == 18 ? 16 : 20) && header.length <= 128,
                    "supported inventory record and reserved bound");
            count++;
        }
        at += header.length;
    }
    require(count == max_net_devices + 1, "all physical devices and loopback fit one reservation");
    if (records)
        *records = count;
    return 0;
}

int main() {
    uint8_t packet[128]{};
    unsigned cases = 0;
    for (uint16_t type : {uint16_t(18), uint16_t(22)}) {
        for (unsigned family : {0u, 2u, 17u}) {
            if (type == 22 && family == 17)
                continue;
            for (unsigned body : {1u, 4u, type == 18 ? 16u : 8u}) {
                memset(packet, 0, sizeof(packet));
                NetlinkHeader header{16 + body, type, 0x301, 456, 999};
                memcpy(packet, &header, sizeof(header));
                packet[16] = family;
                if (body == 4)
                    memset(packet + 17, 0xa5, 3);
                unsigned records = 0;
                require(!evaluate(packet, false, &records) && records == 9,
                        "valid compact and complete dumps");
                require(evaluate(packet, true) == (body == (type == 18 ? 16u : 8u) ? 0 : -22),
                        "strict dump requires the complete header");
                cases++;
            }
        }
    }
    uint32_t state = 0x357194ac;
    for (unsigned mutation = 0; mutation < 16000; mutation++) {
        for (auto& byte : packet) {
            state = state * 1664525 + 1013904223;
            byte = state >> 24;
        }
        NetlinkHeader header{16 + state % 65, uint16_t(state & 1 ? 18 : 22), 0x301, state, 17};
        memcpy(packet, &header, sizeof(header));
        (void)evaluate(packet, state & 2);
    }
    std::printf(
        "NETLINK_INVENTORY_CODEC_PASS valid=%u devices=9 mutations=16000 canaries=checked\n",
        cases);
}
