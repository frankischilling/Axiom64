// SPDX-License-Identifier: GPL-3.0-or-later
#include "net/ipv6/host.hpp"
#include "net/ipv6/configuration.hpp"
#include <algorithm>
#include <array>
#include <cassert>
#include <cstdio>
#include <vector>

using namespace ax;
const std::vector<std::vector<uint8_t>>& ipv6_emitted(unsigned lane);
void ipv6_test_carrier(unsigned lane, bool up);
void ipv6_test_dad_jitter(int value);

namespace {
ip6::Address prefix(unsigned lane, bool link = false) {
    ip6::Address value;
    value.bytes[0] = link ? 0xfe : 0x20;
    value.bytes[1] = link ? 0x80 : 1;
    if (!link) {
        value.bytes[2] = 0x0d;
        value.bytes[3] = 0xb8;
        value.bytes[7] = lane + 1;
    }
    return value;
}

const Ipv6Address* find(unsigned index, const ip6::Address& address) {
    for (unsigned at = 0; auto value = ipv6_address(at); at++)
        if (value->index == index && value->address == address)
            return value;
    return nullptr;
}

unsigned count() {
    unsigned result = 0;
    for (unsigned at = 0; auto value = ipv6_address(at); at++)
        result += !value->address.loopback();
    return result;
}

ip6::Address identifier(unsigned index, ip6::Address network, unsigned counter) {
    assert(!ip6::configuration_stable_identifier(index, network, counter));
    return network;
}

void conflict(unsigned index, const ip6::Address& target) {
    auto destination = ip6::all_nodes();
    std::vector<uint8_t> bytes(86);
    ip6::multicast_mac(destination, bytes.data());
    bytes[6] = 2;
    bytes[10] = index;
    bytes[11] = 0x80;
    bytes[12] = 0x86;
    bytes[13] = 0xdd;
    ip6::Header header{target, destination, 0, 32, 0, 58, 255};
    assert(ip6::encode(bytes.data() + 14, 40, header));
    auto payload = bytes.data() + 54;
    payload[0] = 136;
    payload[4] = 0x20;
    std::copy(target.bytes, target.bytes + 16, payload + 8);
    payload[24] = 2;
    payload[25] = 1;
    std::copy(bytes.begin() + 6, bytes.begin() + 12, payload + 26);
    uint16_t checksum = ip6::checksum(target, destination, 58, payload, 32);
    payload[2] = checksum >> 8;
    payload[3] = checksum;
    ipv6_receive(*net_info(index), bytes.data(), bytes.size());
    ipv6_poll();
}

void probe(unsigned lane, const ip6::Address& target) {
    const auto& output = ipv6_emitted(lane);
    assert(!output.empty());
    const auto& bytes = output.back();
    auto packet = ip6::decode(bytes.data() + 14, bytes.size() - 14);
    assert(packet.input == ip6::Input::payload && packet.protocol == 58 &&
           packet.payload[0] == 135 && packet.header.source.unspecified() &&
           !memcmp(packet.payload + 8, target.bytes, 16));
    assert(!ip6::checksum(packet.header.source, packet.header.destination, 58, packet.payload,
                          packet.length));
}

void capacity_failures(void (*reset)()) {
    for (unsigned lane = 0; lane < 2; lane++)
        for (bool permanent : {false, true}) {
            reset();
            unsigned index = lane + 1;
            auto secret = prefix(9);
            secret.bytes[15] = 0x41;
            assert(!ip6::configuration_secret(index, secret));
            auto original = identifier(index, prefix(lane), 0);
            Ipv6AddressLifetimes lifetime =
                permanent ? Ipv6AddressLifetimes{} : Ipv6AddressLifetimes{60, 120};
            assert(!ipv6_address_add({original, index, 0x800, 64}, lifetime));
            const auto owner = ip6::address_owner(index, original);
            std::array<ip6::Address, ipv6_address_capacity - 1> fillers;
            std::array<uint64_t, ipv6_address_capacity - 1> owners;
            for (unsigned at = 0; at < fillers.size(); at++) {
                fillers[at] = prefix(20);
                fillers[at].bytes[15] = at + 1;
                // NODAD and NOPREFIXROUTE isolate address slots from route slots.
                assert(!ipv6_address_add({fillers[at], 2 - lane, 0x202, 64}));
                owners[at] = ip6::address_owner(2 - lane, fillers[at]);
            }
            assert(count() == ipv6_address_capacity);
            auto overflow = prefix(21);
            overflow.bytes[15] = 1;
            assert(ipv6_address_add({overflow, index, 0x202, 64}) == -105);
            ipv6_poll();
            probe(lane, original);
            conflict(index, original);
            auto expected_retry = identifier(index, prefix(lane), 1);
            assert(!find(index, expected_retry));
            const auto failed = find(index, original);
            assert(bool(failed) == permanent);
            if (failed)
                assert(failed->flags == 0x8c8 && ip6::address_owner(index, original) == owner);
            for (unsigned at = 0; at < fillers.size(); at++)
                assert(ip6::address_owner(2 - lane, fillers[at]) == owners[at] &&
                       ipv6_owned(2 - lane, fillers[at]));
            assert(!ipv6_address_remove(2 - lane, fillers[0]));
            auto emitted = ipv6_emitted(lane).size();
            ticks += 1000;
            ipv6_poll();
            assert(!find(index, expected_retry) && ipv6_emitted(lane).size() == emitted);
            assert(bool(find(index, original)) == permanent);
            assert(!ipv6_address_add({overflow, index, 0x202, 64}));
            assert(ipv6_owned(index, overflow));
            std::printf("IPV6_DAD_CAPACITY lane=%u permanent=%u no_resurrection=1\n", lane,
                        permanent);
        }
}

void changed_secrets(void (*reset)()) {
    using Key = ip6::ConfigurationKey;
    for (unsigned lane = 0; lane < 2; lane++)
        for (bool defaults : {false, true})
            for (bool link : {false, true}) {
                reset();
                unsigned index = lane + 1;
                unsigned scope = defaults ? ip6::configuration_default : index;
                auto first_secret = prefix(9), second_secret = prefix(10);
                assert(!ip6::configuration_secret(scope, first_secret));
                auto network = prefix(lane, link);
                const auto first = identifier(index, network, 0);
                const auto first_retry = identifier(index, network, 1);
                Ipv6AddressLifetimes lifetime =
                    link ? Ipv6AddressLifetimes{} : Ipv6AddressLifetimes{60, 120};
                assert(!ip6::automatic_address({first, index, uint16_t(link ? 0x880 : 0x800), 64},
                                               lifetime));
                ipv6_test_dad_jitter(100);
                ipv6_poll();
                probe(lane, first);
                conflict(index, first);
                const auto owner = ip6::address_owner(index, first_retry);
                assert(owner && find(index, first_retry)->flags == (link ? 0x8c0 : 0x840));
                const auto emitted = ipv6_emitted(lane).size();
                ticks = 100;
                assert(!ip6::configuration_secret(scope, second_secret));
                assert(!ip6::configuration_write(index, Key::generation_mode, 0,
                                                 ip6::ConfigurationWrite::netlink));
                ipv6_poll();
                assert(ip6::address_owner(index, first_retry) == owner &&
                       ipv6_emitted(lane).size() == emitted);
                const auto second_retry = identifier(index, network, 2);
                assert(!(second_retry == identifier(index, network, 1)) &&
                       !(second_retry == first_retry));
                ticks = 201;
                ipv6_poll();
                probe(lane, first_retry);
                conflict(index, first_retry);
                const auto replacement = find(index, second_retry);
                assert(replacement && replacement->flags == (link ? 0x8c0 : 0x840));
                const auto next_owner = ip6::address_owner(index, second_retry);
                assert(next_owner && next_owner != owner);
                const auto copied = ip6::address_lifetimes(index, second_retry, next_owner);
                assert(copied.preferred == lifetime.preferred && copied.valid == lifetime.valid);
                assert(bool(find(index, first_retry)) == link);
                if (link)
                    assert(find(index, first_retry)->flags == 0x8c8 &&
                           ip6::address_owner(index, first_retry) == owner);
                std::printf("IPV6_DAD_SECRET lane=%u default=%u link=%u counter=2\n", lane,
                            defaults, link);
            }
}

void link_lifecycle(void (*reset)()) {
    using Key = ip6::ConfigurationKey;
    for (unsigned lane = 0; lane < 2; lane++)
        for (unsigned action = 0; action < 3; action++) {
            reset();
            unsigned index = lane + 1;
            assert(!ip6::configuration_secret(index, prefix(9)));
            assert(!ip6::configuration_write(index, Key::disabled, 1));
            assert(!ip6::configuration_write(index, Key::disabled, 0));
            const auto first = identifier(index, prefix(lane, true), 0);
            const auto retry = identifier(index, prefix(lane, true), 1);
            auto unrelated = prefix(20);
            unrelated.bytes[15] = 1;
            assert(!ipv6_address_add({unrelated, 2 - lane, 0x202, 64}));
            const auto unrelated_owner = ip6::address_owner(2 - lane, unrelated);
            ipv6_test_dad_jitter(100);
            ipv6_poll();
            probe(lane, first);
            conflict(index, first);
            const auto first_owner = ip6::address_owner(index, first);
            const auto retry_owner = ip6::address_owner(index, retry);
            assert(first_owner && retry_owner);
            const auto emitted = ipv6_emitted(lane).size();
            ticks = 50;
            if (!action)
                ipv6_test_carrier(lane, false);
            else
                assert(!net_configure(index, action == 2, action == 2 ? 1279 : 1500));
            ipv6_poll();
            assert(bool(find(index, first)) == !action && bool(find(index, retry)) == !action);
            ticks = 100;
            ipv6_poll();
            assert(ipv6_emitted(lane).size() == emitted);
            if (!action) {
                ipv6_test_carrier(lane, true);
                ipv6_poll();
                assert(ip6::address_owner(index, first) == first_owner &&
                       ip6::address_owner(index, retry) == retry_owner);
                assert(ipv6_emitted(lane).size() == emitted);
                ticks = 201;
                ipv6_poll();
                probe(lane, retry);
            } else {
                assert(!net_configure(index, true, 1500));
                ipv6_poll();
                assert(ip6::address_owner(index, first) &&
                       ip6::address_owner(index, first) != first_owner && !find(index, retry));
                assert(ipv6_emitted(lane).size() == emitted + 1);
                probe(lane, first);
            }
            assert(ip6::address_owner(2 - lane, unrelated) == unrelated_owner &&
                   ipv6_owned(2 - lane, unrelated));
            std::printf("IPV6_DAD_LINK lane=%u action=%u unrelated_owner_preserved=1\n", lane,
                        action);
        }
}
} // namespace

void ipv6_address_lifecycle_tests(void (*reset)()) {
    capacity_failures(reset);
    changed_secrets(reset);
    link_lifecycle(reset);
    reset();
}
