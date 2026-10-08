// SPDX-License-Identifier: GPL-3.0-or-later
#include <cstdio>
#include <cstdlib>
#include "net/netlink.hpp"

using namespace ax;

static unsigned changes;
static Ipv4Route changed;

static void check(bool condition, const char* reason) {
    if (!condition) {
        std::fprintf(stderr, "NETLINK_CODEC_FAIL %s\n", reason);
        std::exit(1);
    }
}

namespace ax {
const NetInfo* net_info(unsigned index) {
    static NetInfo information[2];
    return index && index <= 2 ? &information[index - 1] : nullptr;
}

int ipv4_route_control(const Ipv4Route& route, bool, bool) {
    changes++;
    changed = route;
    return 0;
}

size_t ipv4_routes(Ipv4Route* output, size_t capacity) {
    size_t count = capacity < 41 ? capacity : 41;
    for (size_t i = 0; i < count; i++)
        output[i] = {uint32_t(0x64400000 + (i << 8)),
                     0xffffff00,
                     0,
                     unsigned(1 + i % 2),
                     unsigned(1000 + i),
                     16,
                     253};
    return count;
}
} // namespace ax

static size_t evaluate(const uint8_t* packet, bool capped, uint8_t* saved) {
    NetlinkHeader request;
    memcpy(&request, packet, sizeof(request));
    size_t capacity = routing_capacity(request);
    auto output = static_cast<uint8_t*>(std::malloc(capacity + 16));
    check(output, "bounded response allocation");
    memset(output, 0xa5, capacity + 16);
    size_t result = routing_reply(packet, 0x12345678, capped, output);
    check(result <= capacity, "response remains inside preallocated capacity");
    for (size_t i = 0; i < 16; i++)
        check(output[capacity + i] == 0xa5, "response canary retained");
    if (result) {
        NetlinkHeader response;
        memcpy(&response, output, sizeof(response));
        check(result >= 16 && response.length >= 16 && response.length <= result &&
                  response.sequence == request.sequence && response.port == 0x12345678,
              "owned response header retains sequence and authoritative port");
        if (saved)
            memcpy(saved, output, result);
    }
    std::free(output);
    return result;
}

int main() {
    uint8_t packet[4096]{}, result[netlink_max_reply]{};
    NetlinkHeader header{52, 24, 1 | 4 | 0x600, 0x89abcdef, 0x76543210};
    const uint8_t route[]{2, 16, 0, 0, 254, 16, 253, 1, 0, 0, 0, 0};
    const uint8_t attributes[]{8,    0, 1, 0, 10, 99, 0, 0, 8, 0, 6, 0,
                               0xe9, 3, 0, 0, 8,  0,  4, 0, 1, 0, 0, 0};
    memcpy(packet, &header, 16);
    memcpy(packet + 16, route, sizeof(route));
    memcpy(packet + 28, attributes, sizeof(attributes));
    check(evaluate(packet, true, result) == 36 && changes == 1 &&
              changed.destination == 0x0a630000 && changed.mask == 0xffff0000 && !changed.gateway &&
              changed.index == 1 && changed.metric == 1001 && changed.protocol == 16 &&
              changed.scope == 253,
          "independent Linux route fixture reaches storage with owned scalar values");
    for (unsigned i = 16; i < 28; i++) {
        uint8_t truncated[4096]{};
        memcpy(truncated, packet, sizeof(packet));
        NetlinkHeader short_header = header;
        short_header.length = i;
        memcpy(truncated, &short_header, sizeof(short_header));
        unsigned before = changes;
        check(evaluate(truncated, true, result) == 36 && changes == before,
              "truncated routing body never changes route storage");
    }
    header.type = 26;
    header.flags = 1 | 0x300;
    header.length = 28;
    memcpy(packet, &header, sizeof(header));
    packet[17] = packet[22] = packet[23] = 0;
    size_t dumped = evaluate(packet, true, result), records = 0;
    for (size_t at = 0; at < dumped;) {
        NetlinkHeader record;
        memcpy(&record, result + at, sizeof(record));
        check(record.length >= 16 && record.length <= dumped - at,
              "maximum routing snapshot has complete aligned records");
        if (record.type == 3)
            check(record.length == 20 && at + record.length == dumped,
                  "maximum dump terminates with one complete status");
        else {
            check(record.type == 24 && record.flags == 2,
                  "route dump records use multipart route metadata");
            records++;
        }
        at += record.length;
    }
    check(records == 41, "connected and explicit route snapshot fits reserved capacity");
    header = {17, 0x777, 5, 88, 77};
    memcpy(packet, &header, sizeof(header));
    packet[16] = 'A';
    check(evaluate(packet, false, result) == 40 && !result[37] && !result[38] && !result[39],
          "uncapped error alignment never exposes uninitialized kernel bytes");
    std::puts("NETLINK_CODEC_FIXTURES_PASS");
    uint32_t random = 0xc013d00d;
    for (unsigned trial = 0; trial < 20000; trial++) {
        uint8_t input[4096]{};
        header = {52, 24, 1 | 4 | 0x600, trial, 77};
        memcpy(input, &header, sizeof(header));
        memcpy(input + 16, route, sizeof(route));
        memcpy(input + 28, attributes, sizeof(attributes));
        if (trial % 4 == 2) {
            header.length = 28;
            input[17] = input[22] = input[23] = 0;
            memcpy(input, &header, sizeof(header));
        }
        for (unsigned i = 0; i < 11; i++) {
            random = random * 1664525 + 1013904223;
            size_t offset = (random >> 8) % (i % 3 ? header.length : sizeof(input));
            input[offset] ^= uint8_t(random >> 24);
        }
        memcpy(&header, input, sizeof(header));
        header.length = trial % 3 == 0   ? 16 + (random % (sizeof(input) - 15))
                        : trial % 4 == 2 ? 28
                                         : 52;
        header.type = trial % 4 == 0 ? 24 : trial % 4 == 1 ? 25 : trial % 4 == 2 ? 26 : 0x777;
        header.flags = 1 | 4 | (trial % 4 == 0 ? 0x600 : trial % 4 == 2 ? 0x300 : 0);
        memcpy(input, &header, sizeof(header));
        evaluate(input, trial & 1, nullptr);
    }
    std::puts("NETLINK_CODEC_MUTATIONS_PASS count=20000");
}
