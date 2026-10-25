// SPDX-License-Identifier: GPL-3.0-or-later
#include "net/packet.hpp"
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include "../../net/packet.cpp"

namespace ax {
void* alloc(size_t size) {
    return std::malloc(size);
}

void release(void* data) {
    std::free(data);
}

void clock_refresh(bool) {
    std::abort();
}

uint64_t clock_realtime_ticks() {
    std::abort();
}
} // namespace ax

int main(int argc, char** argv) {
    assert(argc == 3);
    FILE* input = std::fopen(argv[2], "rb");
    assert(input);
    unsigned char actual_probe[1518];
    size_t length = std::fread(actual_probe, 1, sizeof(actual_probe), input);
    assert(length == 86 && std::feof(input) && std::fclose(input) == 0);
    assert(actual_probe[12] == 0x86 && actual_probe[13] == 0xdd && actual_probe[54] == 135);
    using namespace ax;
    bool outgoing = !strcmp(argv[1], "outgoing");
    assert(outgoing || !strcmp(argv[1], "incoming"));
    NetInfo info{};
    info.index = 1;
    const uint16_t protocols[] = {3, 0x86dd, 0x0800, 3, 0x86dd, 3, 3, 0, 0x86dd, 3};
    for (unsigned at = 0; at < 10; at++) {
        auto& socket = sockets[at];
        socket = {};
        socket.used = true;
        socket.index = (at == 5) ? 2 : (at == 6 || at == 8) ? 0 : 1;
        socket.protocol = network_protocol(protocols[at]);
        socket.ignore_outgoing = at == 3 || at == 4;
    }
    unsigned type = outgoing ? 4 : 2;
    packet_deliver(info, actual_probe, length, type, outgoing ? &sockets[9] : nullptr);
    const unsigned expected_outgoing[] = {1, 0, 0, 0, 0, 0, 1, 0, 0, 0};
    const unsigned expected_incoming[] = {1, 1, 0, 1, 1, 0, 1, 0, 1, 1};
    const auto expected = outgoing ? expected_outgoing : expected_incoming;
    bool correct = true;
    std::printf("PACKET_PROTOCOL_MODEL direction=%s counts=", argv[1]);
    for (unsigned at = 0; at < 10; at++) {
        auto& socket = sockets[at];
        std::printf("%s%u", at ? "," : "", socket.count);
        correct &=
            socket.count == expected[at] && socket.packets == expected[at] && !socket.dropped;
        if (socket.count) {
            const auto frame = packet_front(&socket);
            assert(frame && frame->source.family == 17 && frame->source.index == 1 &&
                   frame->source.type == type &&
                   frame->source.protocol == network_protocol(0x86dd) && frame->length == length &&
                   !memcmp(packet_bytes(frame), actual_probe, length));
        }
        packet_close(&socket);
        assert(!socket.count && !socket.bytes);
    }
    std::printf(" passed=%s\n", correct ? "true" : "false");
    return correct ? 0 : 1;
}
