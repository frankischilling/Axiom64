// SPDX-License-Identifier: GPL-3.0-or-later
#include "net/ipv4/reassembly.hpp"
#include "net/ipv4_wire.hpp"
#include <algorithm>
#include <array>
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <random>
#include <unordered_set>
#include <vector>

using namespace ax::ip4;

namespace {
std::unordered_set<void*> allocations;
int allowance = -1;
unsigned checks;
std::vector<std::vector<uint8_t>> expired_quotes;
std::vector<unsigned> expired_indices;
std::vector<bool> expired_broadcast;
} // namespace

namespace ax {
void* alloc(size_t length) {
    if (!allowance)
        return nullptr;
    if (allowance > 0)
        allowance--;
    void* value = std::malloc(length);
    assert(value && allocations.insert(value).second);
    return value;
}

void release(void* value) {
    if (!value)
        return;
    assert(allocations.erase(value) == 1);
    std::free(value);
}
} // namespace ax

static void checksum_header(std::vector<uint8_t>& packet) {
    put16(packet.data() + 10, 0);
    put16(packet.data() + 10, checksum(packet.data(), (packet[0] & 15) * 4));
}

static std::vector<uint8_t> fragment(size_t offset, size_t length, bool more, unsigned id = 1,
                                     unsigned header = 20, uint8_t ecn = 0, bool df = false) {
    assert(header >= 20 && header <= 60 && header % 4 == 0 && offset % 8 == 0);
    assert(header + length <= 65535);
    std::vector<uint8_t> packet(header + length);
    packet[0] = 0x40 | (header / 4);
    packet[1] = 0xa0 | ecn;
    put16(packet.data() + 2, packet.size());
    put16(packet.data() + 4, id);
    put16(packet.data() + 6, offset / 8 | (more ? 0x2000 : 0) | (df ? 0x4000 : 0));
    packet[8] = 64;
    packet[9] = 17;
    put32(packet.data() + 12, 0x0a170101);
    put32(packet.data() + 16, 0x0a170102);
    for (size_t i = 0; i < length; i++)
        packet[header + i] = uint8_t((offset + i) * 17 + 3);
    checksum_header(packet);
    return packet;
}

static Reassembled submit(const std::vector<uint8_t>& packet, unsigned index = 1,
                          uint64_t now = 100, bool broadcast = false) {
    return reassemble(index, packet.data(), packet.size(), now, broadcast);
}

static void verify(Reassembled result, size_t payload, unsigned header = 20,
                   uint32_t destination = 0x0a170102) {
    assert(result.status == FragmentStatus::complete && result.bytes);
    assert(result.length == header + payload && get16(result.bytes + 2) == result.length);
    assert((unsigned(result.bytes[0]) & 15) * 4 == header && !checksum(result.bytes, header));
    assert(!(get16(result.bytes + 6) & 0x3fff));
    assert(get32(result.bytes + 12) == 0x0a170101 && get32(result.bytes + 16) == destination);
    for (size_t i = 0; i < payload; i++)
        assert(result.bytes[header + i] == uint8_t(i * 17 + 3));
    ax::release(result.bytes);
    checks++;
}

static void clean() {
    reassembly_discard();
    assert(allocations.empty());
    allowance = -1;
    expired_quotes.clear();
    expired_indices.clear();
    expired_broadcast.clear();
}

static void on_expired(unsigned index, const uint8_t* bytes, size_t length, bool broadcast) {
    expired_quotes.emplace_back(bytes, bytes + length);
    expired_indices.push_back(index);
    expired_broadcast.push_back(broadcast);
}

static void ordering() {
    std::array<unsigned, 3> order{0, 1, 2};
    do {
        std::array<std::vector<uint8_t>, 3> packets{fragment(0, 16, true), fragment(16, 16, true),
                                                    fragment(32, 11, false)};
        for (unsigned i = 0; i < order.size(); i++) {
            auto result = submit(packets[order[i]]);
            // Recycling the caller's RX storage cannot change accepted bytes.
            std::fill(packets[order[i]].begin(), packets[order[i]].end(), 0xcc);
            if (i == 2)
                verify(result, 43);
            else
                assert(result.status == FragmentStatus::pending && !result.bytes);
        }
        clean();
    } while (std::next_permutation(order.begin(), order.end()));

    auto first = fragment(0, 16, true);
    assert(submit(first).status == FragmentStatus::pending);
    auto repeated = submit(first);
    assert(repeated.status == FragmentStatus::duplicate && !repeated.bytes);
    auto tail = fragment(16, 7, false);
    tail.resize(tail.size() + 12, 0xdd); // Ethernet padding is outside IP total length.
    verify(submit(tail), 23);
    clean();

    assert(submit(fragment(0, 24, true)).status == FragmentStatus::pending);
    assert(submit(fragment(8, 8, true)).status == FragmentStatus::duplicate);
    verify(submit(fragment(24, 5, false)), 29);
    clean();
}

static void invalid_overlap() {
    for (bool conflict : {false, true}) {
        assert(submit(fragment(0, 16, true)).status == FragmentStatus::pending);
        auto packet = fragment(conflict ? 0 : 8, 16, true);
        if (conflict)
            packet.back() ^= 1;
        assert(submit(packet).status == FragmentStatus::rejected);
        assert(allocations.empty());
        // A later tail cannot complete the invalidated datagram.
        assert(submit(fragment(24, 3, false)).status == FragmentStatus::pending);
        clean();
    }
    assert(submit(fragment(16, 8, false)).status == FragmentStatus::pending);
    assert(submit(fragment(24, 8, false)).status == FragmentStatus::rejected);
    assert(allocations.empty());
    assert(submit(fragment(8, 16, true)).status == FragmentStatus::pending);
    assert(submit(fragment(16, 8, false)).status == FragmentStatus::rejected);
    clean();
    assert(submit(fragment(16, 8, false)).status == FragmentStatus::pending);
    assert(submit(fragment(24, 8, true)).status == FragmentStatus::rejected);
    clean();
    assert(submit(fragment(16, 8, false)).status == FragmentStatus::pending);
    assert(submit(fragment(0, 24, true)).status == FragmentStatus::rejected);
    clean();
    checks += 8;
}

static void malformed() {
    auto original = fragment(0, 8, true);
    for (size_t length = 0; length < original.size(); length++) {
        assert(reassemble(1, original.data(), length, 100).status == FragmentStatus::rejected);
        assert(allocations.empty());
        checks++;
    }
    assert(reassemble(1, nullptr, 100, 100).status == FragmentStatus::rejected);
    assert(submit(original, 0).status == FragmentStatus::rejected);
    for (unsigned at : {0u, 2u, 8u, 10u, 12u, 16u}) {
        auto broken = original;
        broken[at] ^= 1;
        assert(submit(broken).status == FragmentStatus::rejected);
        assert(allocations.empty());
    }
    for (unsigned kind = 0; kind < 5; kind++) {
        auto packet = original;
        if (kind == 0)
            packet[0] = 0x44;
        if (kind == 1)
            packet[8] = 0;
        if (kind == 2)
            put16(packet.data() + 6, 0xa000);
        if (kind == 3)
            put16(packet.data() + 2, 19);
        if (kind == 4)
            put16(packet.data() + 2, packet.size() + 1);
        checksum_header(packet);
        assert(submit(packet).status == FragmentStatus::rejected);
        assert(allocations.empty());
    }
    assert(submit(fragment(0, 7, true)).status == FragmentStatus::rejected);
    assert(submit(fragment(8, 0, false)).status == FragmentStatus::rejected);
    assert(submit(fragment(65528, 8, false)).status == FragmentStatus::rejected);
    assert(allocations.empty());

    // A corrupt header does not evict the valid partial packet with the same ID.
    assert(submit(original).status == FragmentStatus::pending);
    auto corrupt = fragment(8, 8, false);
    corrupt[10] ^= 1;
    assert(submit(corrupt).status == FragmentStatus::rejected);
    verify(submit(fragment(8, 8, false)), 16);
    clean();
    checks += 17;
}

static void boundaries_and_headers() {
    assert(submit(fragment(0, 65512, true)).status == FragmentStatus::pending);
    verify(submit(fragment(65512, 3, false)), 65515);
    clean();
    assert(submit(fragment(65472, 3, false)).status == FragmentStatus::pending);
    verify(submit(fragment(0, 65472, true, 1, 60)), 65475, 60);
    clean();
}

static void extended_headers() {
    assert(submit(fragment(65472, 3, false)).status == FragmentStatus::pending);
    verify(submit(fragment(0, 65472, true, 1, 60)), 65475, 60);
    clean();
    assert(submit(fragment(65512, 3, false)).status == FragmentStatus::pending);
    assert(submit(fragment(0, 8, true, 1, 60)).status == FragmentStatus::rejected);
    assert(allocations.empty());
    assert(submit(fragment(0, 8, true, 1, 60)).status == FragmentStatus::pending);
    assert(submit(fragment(65512, 3, false)).status == FragmentStatus::rejected);
    clean();
    for (unsigned header = 20; header <= 60; header += 4) {
        assert(submit(fragment(16, 8, false)).status == FragmentStatus::pending);
        verify(submit(fragment(0, 16, true, 1, header)), 24, header);
        clean();
    }
    checks += 2;
}

static void tuple_ownership() {
    auto first = fragment(0, 8, true);
    // Physical ingress is not part of the RFC 791 source/destination/protocol/ID key.
    assert(submit(first, 1).status == FragmentStatus::pending);
    verify(submit(fragment(8, 8, false), 2), 16);
    assert(allocations.empty());
    assert(submit(first, 1).status == FragmentStatus::pending);
    assert(submit(fragment(8, 8, false, 2), 1).status == FragmentStatus::pending);
    auto wrong = fragment(8, 8, false);
    wrong[9] = 1;
    checksum_header(wrong);
    assert(submit(wrong).status == FragmentStatus::pending);
    for (unsigned at : {12u, 16u}) {
        wrong = fragment(8, 8, false);
        wrong[at + 3]++;
        checksum_header(wrong);
        assert(submit(wrong).status == FragmentStatus::pending);
    }
    assert(allocations.size() == 5);
    verify(submit(fragment(8, 8, false)), 16);
    assert(allocations.size() == 4);
    clean();
}

static void lifetimes() {
    assert(submit(fragment(0, 8, true), 1, 1000).status == FragmentStatus::pending);
    assert(submit(fragment(0, 8, true), 1, 6999).status == FragmentStatus::duplicate);
    reassembly_expire(6999, on_expired);
    assert(expired_quotes.empty() && allocations.size() == 1);
    reassembly_expire(7000, on_expired);
    assert(allocations.empty() && expired_quotes.size() == 1 && expired_indices[0] == 1);
    auto first = fragment(0, 8, true);
    assert(expired_quotes[0] == first && !expired_broadcast[0]);
    clean();
    assert(submit(fragment(8, 8, false)).status == FragmentStatus::pending);
    reassembly_expire(6100, on_expired);
    assert(allocations.empty() && expired_quotes.empty());
    clean();
    assert(submit(first).status == FragmentStatus::pending);
    auto other_first = first;
    put32(other_first.data() + 16, 0x0a170202);
    checksum_header(other_first);
    assert(submit(other_first, 2).status == FragmentStatus::pending);
    reassembly_discard(0x0a170102);
    assert(allocations.size() == 1);
    auto other_tail = fragment(8, 8, false);
    put32(other_tail.data() + 16, 0x0a170202);
    checksum_header(other_tail);
    verify(submit(other_tail, 2), 16, 20, 0x0a170202);
    clean();

    for (bool df : {false, true}) {
        assert(submit(first).status == FragmentStatus::pending);
        assert(submit(fragment(0, 3, false, 1, 20, 0, df)).status == FragmentStatus::whole);
        // A complete datagram's reused ID cannot retire another fragmented one.
        assert(allocations.size() == 1);
        verify(submit(fragment(8, 8, false)), 16);
        clean();
    }
    // Admission expires old ownership before considering the new same-ID tail.
    assert(submit(first).status == FragmentStatus::pending);
    auto tail = fragment(8, 8, false);
    assert(reassemble(1, tail.data(), tail.size(), 6100, false, on_expired).status ==
           FragmentStatus::pending);
    assert(expired_quotes.size() == 1 && allocations.size() == 1);
    clean();

    assert(submit(first, 1, 100, true).status == FragmentStatus::pending);
    auto result = submit(tail);
    assert(result.link_broadcast);
    verify(result, 16);
    clean();
    assert(submit(first, 2, 100, true).status == FragmentStatus::pending);
    reassembly_expire(6100, on_expired);
    assert(expired_indices == std::vector<unsigned>{2} && expired_broadcast[0]);
    clean();
    checks += 7;
}

static void resources() {
    for (unsigned id = 1; id <= reassembly_capacity; id++)
        assert(submit(fragment(0, 8, true, id)).status == FragmentStatus::pending);
    assert(allocations.size() == reassembly_capacity);
    assert(submit(fragment(0, 8, true, reassembly_capacity + 1)).status ==
           FragmentStatus::exhausted);
    // Exhaustion preserves earlier queues; completing one makes room immediately.
    verify(submit(fragment(8, 8, false)), 16);
    assert(submit(fragment(0, 8, true, reassembly_capacity + 1)).status == FragmentStatus::pending);
    clean();
    allowance = 0;
    assert(submit(fragment(0, 8, true)).status == FragmentStatus::exhausted);
    assert(allocations.empty());
    allowance = 1;
    assert(submit(fragment(0, 8, true)).status == FragmentStatus::pending);
    assert(submit(fragment(8, 8, false)).status == FragmentStatus::exhausted);
    assert(allocations.empty());
    clean();
    checks += 3;
}

static void congestion_and_df() {
    for (unsigned mask = 1; mask < 16; mask++) {
        std::vector<unsigned> codes;
        for (unsigned ecn = 0; ecn < 4; ecn++)
            if (mask & (1u << ecn))
                codes.push_back(ecn);
        if (codes.size() == 1)
            codes.push_back(codes[0]);
        bool rejected = false;
        for (size_t i = 0; i < codes.size(); i++) {
            auto result = submit(fragment(i * 8, 8, i + 1 != codes.size(), 1, 20, codes[i]));
            if (result.status == FragmentStatus::rejected) {
                rejected = true;
                break;
            }
            if (i + 1 == codes.size()) {
                assert(result.status == FragmentStatus::complete);
                unsigned expected = mask & 8 ? 3 : codes[0];
                assert((result.bytes[1] & 3) == expected && (result.bytes[1] & 0xfc) == 0xa0);
                verify(result, codes.size() * 8);
            }
        }
        assert(rejected == ((mask & 1) && mask != 1));
        clean();
        checks++;
    }
    assert(submit(fragment(0, 16, true, 1, 20, 0, true)).status == FragmentStatus::pending);
    auto result = submit(fragment(16, 8, false));
    assert(get16(result.bytes + 6) == 0x4000);
    verify(result, 24);
    clean();
    assert(submit(fragment(0, 8, true, 1, 20, 0, true)).status == FragmentStatus::pending);
    result = submit(fragment(8, 16, false));
    assert(get16(result.bytes + 6) == 0);
    verify(result, 24);
    clean();
}

static void randomized() {
    std::mt19937 random(0x4176);
    for (unsigned trial = 0; trial < 128; trial++) {
        size_t length = 1 + random() % 65515;
        if (length < 9)
            length = 9;
        std::vector<std::vector<uint8_t>> pieces;
        for (size_t at = 0; at < length;) {
            size_t count = std::min<size_t>(length - at, (1 + random() % 128) * 8);
            if (pieces.empty() && count == length)
                count = (length - 1) & ~size_t(7);
            pieces.push_back(fragment(at, count, at + count != length));
            at += count;
        }
        std::shuffle(pieces.begin(), pieces.end(), random);
        for (size_t i = 0; i < pieces.size(); i++) {
            auto result = submit(pieces[i]);
            if (i + 1 == pieces.size())
                verify(result, length);
            else
                assert(result.status == FragmentStatus::pending);
        }
        clean();
    }
}

static void processed_options_ownership() {
    for (bool timestamp : {false, true}) {
        for (bool reversed : {false, true}) {
            auto first = fragment(0, 16, true, 17, 28);
            auto last = fragment(16, 8, false, 17);
            const uint8_t record[] = {7, 7, 4, 0, 0, 0, 0, 0};
            const uint8_t time[] = {68, 8, 5, 0, 0, 0, 0, 0};
            std::memcpy(first.data() + 20, timestamp ? time : record, 8);
            checksum_header(first);
            ReceivedOptions processed;
            assert(!processed.assign(first.data() + 20, 8, 0x0a170101, 0x0a170102, 1000));
            const auto expected = processed;
            if (reversed)
                assert(submit(last).status == FragmentStatus::pending);
            auto result =
                reassemble(1, first.data(), first.size(), 100, false, nullptr, &processed);
            assert(!processed.assign(first.data() + 20, 8, 0x0a170101, 0x0a170103, 9000));
            std::fill(first.begin(), first.end(), 0xcc);
            if (!reversed) {
                assert(result.status == FragmentStatus::pending);
                result = submit(last, 1, 500);
            }
            assert(result.status == FragmentStatus::complete && result.options_processed);
            assert(result.options.size() == 8 &&
                   !std::memcmp(result.options.data(), expected.data(), 8));
            assert(!std::memcmp(result.bytes + 20, expected.data(), 8));
            assert(result.options.return_valid() == expected.return_valid() &&
                   result.options.reply().size() == expected.reply().size() &&
                   !std::memcmp(result.options.reply().data(), expected.reply().data(),
                                expected.reply().size()));
            verify(result, 24, 28);
            clean();
        }
    }
    ReceivedOptions processed;
    const uint8_t record[] = {7, 7, 4, 0, 0, 0, 0, 0};
    assert(!processed.assign(record, 8, 0x0a170101, 0x0a170102, 1000));
    auto first = fragment(0, 16, true);
    assert(reassemble(1, first.data(), first.size(), 100, false, nullptr, &processed).status ==
           FragmentStatus::rejected);
    first = fragment(0, 16, true, 17, 28);
    std::memcpy(first.data() + 20, record, 8);
    checksum_header(first);
    first[10] ^= 1;
    assert(reassemble(1, first.data(), first.size(), 100, false, nullptr, &processed).status ==
           FragmentStatus::rejected);
    clean();
    puts("IPV4_REASSEMBLY_OPTIONS_PASS first_fragment owned_metadata timestamps "
         "original_wire_validation");
}

int main() {
    processed_options_ownership();
    ordering();
    invalid_overlap();
    malformed();
    boundaries_and_headers();
    extended_headers();
    tuple_ownership();
    lifetimes();
    resources();
    congestion_and_df();
    randomized();
    clean();
    std::printf("IPv4 reassembly: %u checks passed; all allocations released\n", checks);
}
