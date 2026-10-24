// SPDX-License-Identifier: GPL-3.0-or-later
#include "net/netlink.hpp"
#include "net/ipv6/configuration.hpp"
#include <algorithm>
#include <cassert>
#include <cstdio>
#include <vector>

using namespace ax;

namespace {
unsigned requests;

void attribute(std::vector<uint8_t>& bytes, uint16_t type, const std::vector<uint8_t>& data) {
    uint16_t size = 4 + data.size();
    size_t at = bytes.size();
    bytes.resize(at + ((size + 3u) & ~3u));
    memcpy(bytes.data() + at, &size, 2);
    memcpy(bytes.data() + at + 2, &type, 2);
    if (!data.empty())
        memcpy(bytes.data() + at + 4, data.data(), data.size());
}

std::vector<uint8_t> change(unsigned index, unsigned mode, unsigned length = 1, unsigned shape = 0,
                            bool nested = true) {
    std::vector<uint8_t> inner, families, bytes(32);
    if (!shape || shape == 3) {
        std::vector<uint8_t> value(length, 0xa5);
        if (length)
            value[0] = mode;
        attribute(inner, 8, value);
    }
    if (shape == 1 || shape == 3)
        attribute(inner, 2, {2, 0, 0, 0});
    if (shape == 4)
        attribute(inner, 99, {1});
    attribute(families, 10 | (nested ? 0x8000 : 0), inner);
    attribute(bytes, 26 | (nested ? 0x8000 : 0), families);
    NetlinkHeader header{uint32_t(bytes.size()), 16, 5, 0x12345678, 0};
    memcpy(bytes.data(), &header, sizeof(header));
    memcpy(bytes.data() + 20, &index, 4);
    return bytes;
}

int submit(const std::vector<uint8_t>& bytes, bool privileged = true, bool capped = false) {
    NetlinkHeader header;
    memcpy(&header, bytes.data(), sizeof(header));
    size_t capacity = routing_capacity(header, bytes.data());
    std::vector<uint8_t> reply(capacity + 16, 0xa5);
    size_t size = routing_reply(bytes.data(), 71, capped, reply.data(), privileged);
    assert(size >= 36 && size <= capacity);
    assert(
        std::all_of(reply.begin() + capacity, reply.end(), [](auto byte) { return byte == 0xa5; }));
    NetlinkHeader response;
    memcpy(&response, reply.data(), sizeof(response));
    assert(response.type == 2 && response.length == size && response.sequence == header.sequence &&
           response.port == 71);
    int error;
    memcpy(&error, reply.data() + 16, 4);
    requests++;
    return error;
}

int mode(unsigned index) {
    int32_t value = -1;
    assert(!ip6::configuration_read(index, ip6::ConfigurationKey::generation_mode, value));
    return value;
}

bool automatic(unsigned index) {
    for (unsigned at = 0; auto entry = ipv6_address(at); at++)
        if (entry->index == index && entry->address.link_local())
            return true;
    return false;
}

void query(unsigned index, unsigned family, bool dump, bool ack) {
    uint8_t input[32]{};
    NetlinkHeader request{sizeof(input), 18, uint16_t(1 | (dump ? 0x300 : 0) | (ack ? 4 : 0)),
                          0x13572468, 0};
    memcpy(input, &request, sizeof(request));
    input[16] = family;
    if (!dump)
        memcpy(input + 20, &index, 4);
    std::vector<uint8_t> output(netlink_family_reply + 16, 0xa5);
    size_t size = routing_reply(input, 72, false, output.data(), false, true);
    assert(size <= netlink_family_reply &&
           std::all_of(output.begin() + netlink_family_reply, output.end(),
                       [](auto byte) { return byte == 0xa5; }));
    unsigned links = 0, endings = 0;
    for (size_t at = 0; at < size;) {
        NetlinkHeader response;
        assert(size - at >= sizeof(response));
        memcpy(&response, output.data() + at, sizeof(response));
        assert(response.length <= size - at && response.length >= sizeof(response) &&
               response.sequence == request.sequence && response.port == 72);
        if (response.type != 16) {
            assert(response.length >= 20);
            int error = -1;
            memcpy(&error, output.data() + at + 16, 4);
            assert(!error && at + response.length == size && response.type == (dump ? 3 : 2) &&
                   (dump || ack));
            endings++;
        } else {
            assert(response.length >= 32 && response.flags == (dump ? 2 : 0));
            assert(output[at + 16] == (dump && family == 10 ? 10 : 0));
            unsigned selected;
            memcpy(&selected, output.data() + at + 20, 4);
            assert(dump || selected == index);
            bool found = false;
            for (size_t field = at + 32; field < at + response.length;) {
                uint16_t length, type;
                memcpy(&length, output.data() + field, 2);
                memcpy(&type, output.data() + field + 2, 2);
                assert(length >= 4 && length <= at + response.length - field);
                if (type == (dump && family == 10 ? 12 : 26)) {
                    size_t inner = field + (type == 26 ? 8 : 4);
                    assert(length == (type == 26 ? 16 : 12) && output[inner] == 5 &&
                           !output[inner + 1] && output[inner + 2] == 8 && !output[inner + 3] &&
                           output[inner + 4] == mode(selected));
                    found = true;
                }
                field += (length + 3u) & ~3u;
            }
            assert(found);
            links++;
        }
        at += (response.length + 3u) & ~3u;
    }
    unsigned expected = 1;
    if (dump) {
        for (unsigned at = 1; at <= max_net_devices; at++)
            expected += net_info(at) != nullptr;
    }
    if (links != expected || endings != unsigned(dump || ack))
        std::fprintf(stderr, "link query index=%u family=%u dump=%u ack=%u links=%u endings=%u\n",
                     index, family, dump, ack, links, endings);
    assert(links == expected && endings == unsigned(dump || ack));
    requests++;
}
} // namespace

void ipv6_link_configuration_tests(void (*reset)()) {
    requests = 0;
    for (unsigned index : {1u, 2u}) {
        reset();
        assert(mode(index) == 1 && !automatic(index));
        assert(!submit(change(index, 0)) && mode(index) == 0 && !automatic(index));
        assert(mode(3 - index) == 1);
        assert(!net_configure(index, false, 1500) && !net_configure(index, true, 1500));
        assert(automatic(index));
        assert(!submit(change(index, 1)) && mode(index) == 1 && automatic(index));
        for (auto invalid : {4u, 255u})
            assert(submit(change(index, invalid)) == -22 && mode(index) == 1);
        assert(submit(change(index, 2)) == -22 && mode(index) == 1);
        assert(submit(change(index, 0, 0)) == -34 && mode(index) == 1);
        assert(!submit(change(index, 0, 2)) && mode(index) == 0);
        assert(!submit(change(index, 1, 4)) && mode(index) == 1);
        for (unsigned shape : {1u, 2u, 4u})
            assert(submit(change(index, 0, 1, shape)) == -22 && mode(index) == 1);
        assert(!submit(change(index, 0, 1, 3)) && mode(index) == 0);
        assert(!submit(change(index, 1, 1, 0, false)) && mode(index) == 1);
        auto family = change(index, 0);
        family[16] = 10;
        assert(!submit(family) && mode(index) == 0);
        assert(submit(change(999, 0)) == -19 && mode(index) == 0);
        assert(submit(change(index, 1), false) == -1 && mode(index) == 0);
        assert(submit(change(index, 1), false, true) == -1 && mode(index) == 0);
        for (unsigned family : {0u, 10u}) {
            query(index, family, false, false);
            query(index, family, false, true);
            query(index, family, true, false);
        }
        for (size_t at : {32u, 36u, 40u}) {
            for (unsigned length : {0u, 3u, 255u, 65535u}) {
                auto damaged = change(index, 1);
                damaged[at] = length;
                damaged[at + 1] = length >> 8;
                assert(submit(damaged) < 0 && mode(index) == 0);
            }
        }
        auto later = change(index, 1);
        later.push_back(0xff);
        uint32_t size = later.size();
        memcpy(later.data(), &size, 4);
        assert(submit(later) == -22 && mode(index) == 0);
    }
    reset();
    std::printf("IPV6_LINK_CONFIGURATION_PASS requests=%u adapters=2 atomic_errors=checked "
                "replies=checked\n",
                requests);
}
