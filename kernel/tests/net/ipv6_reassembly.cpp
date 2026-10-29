// SPDX-License-Identifier: GPL-3.0-or-later
#include "net/ipv6/reassembly.hpp"
#include <algorithm>
#include <array>
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <random>
#include <unordered_set>
#include <vector>

using namespace ax::ip6;

namespace {
std::unordered_set<void*> allocations;
int allowance = -1;
unsigned checks;
std::vector<std::vector<uint8_t>> quotes;
std::vector<unsigned> quote_indices;
} // namespace

namespace ax {
void* alloc(size_t length) {
    if (!allowance)
        return nullptr;
    if (allowance > 0)
        allowance--;
    auto value = std::malloc(length);
    assert(value && allocations.insert(value).second);
    return value;
}

void release(void* value) {
    if (value) {
        assert(allocations.erase(value) == 1);
        std::free(value);
    }
}
} // namespace ax

static void put16(uint8_t* bytes, size_t value) {
    bytes[0] = value >> 8;
    bytes[1] = value;
}

static std::vector<uint8_t> fragment(size_t offset, size_t length, bool more, unsigned id = 1,
                                     size_t prefix = 0, unsigned ecn = 0, uint8_t protocol = 17,
                                     size_t total = 53) {
    assert(offset % 8 == 0 && prefix % 8 == 0 && prefix <= 2048);
    std::vector<uint8_t> bytes(48 + prefix + length);
    Header header;
    header.source.bytes[0] = header.destination.bytes[0] = 0x20;
    header.source.bytes[1] = header.destination.bytes[1] = 1;
    header.source.bytes[15] = 1;
    header.destination.bytes[15] = 2;
    header.payload_length = bytes.size() - 40;
    header.next_header = prefix ? 60 : 44;
    header.traffic_class = 0xa0 | ecn;
    assert(encode(bytes.data(), bytes.size(), header));
    if (prefix) {
        bytes[40] = 44;
        bytes[41] = prefix / 8 - 1;
    }
    auto field = bytes.data() + 40 + prefix;
    field[0] = protocol;
    put16(field + 2, offset | unsigned(more));
    for (unsigned n = 0; n < 4; n++)
        field[4 + n] = id >> (24 - n * 8);
    for (size_t n = 0; n < length; n++)
        field[8 + n] = uint8_t((offset + n) * 17 + 3);
    if (!offset && protocol == 17 && length >= 8) {
        put16(field + 8, 5000);
        put16(field + 10, 5001);
        put16(field + 12, total);
        put16(field + 14, 0x1234);
    }
    return bytes;
}

static Reassembled submit(const std::vector<uint8_t>& bytes, unsigned index = 1,
                          uint64_t now = 100) {
    checks++;
    return reassemble(index, bytes.data(), bytes.size(), now);
}

static void complete(Reassembled result, size_t size = 53, size_t prefix = 0, unsigned ecn = 0) {
    assert(result.status == FragmentStatus::complete && result.bytes);
    assert(result.length == 40 + prefix + size);
    auto packet = decode(result.bytes, result.length);
    assert(packet.input == Input::payload && !packet.fragmented && packet.protocol == 17);
    assert(packet.header.traffic_class == (0xa0 | ecn) && packet.length == size);
    auto expected = fragment(0, size, false, 1, prefix, ecn);
    assert(!std::memcmp(packet.payload, expected.data() + 48 + prefix, size));
    assert(result.bytes[prefix ? 40 : 6] == 17);
    ax::release(result.bytes);
    checks++;
}

static void clean() {
    reassembly_discard();
    assert(allocations.empty());
    allowance = -1;
    quotes.clear();
    quote_indices.clear();
}

static void expired(unsigned index, const uint8_t* bytes, size_t size) {
    quotes.emplace_back(bytes, bytes + size);
    quote_indices.push_back(index);
    reassembly_discard(); // Notification must not retain a live queue slot.
}

static void ordering_and_prefixes() {
    std::array<unsigned, 4> order{0, 1, 2, 3};
    do {
        for (size_t prefix : {size_t(0), size_t(8), size_t(16)}) {
            for (unsigned at = 0; at < order.size(); at++) {
                unsigned piece = order[at];
                auto result =
                    submit(fragment(piece * 16, piece == 3 ? 5 : 16, piece != 3, 7, prefix));
                if (at == 3)
                    complete(result, 53, prefix);
                else
                    assert(result.status == FragmentStatus::pending && !result.bytes);
            }
            clean();
        }
    } while (std::next_permutation(order.begin(), order.end()));
    assert(submit(fragment(16, 37, false, 1, 8)).status == FragmentStatus::pending);
    complete(submit(fragment(0, 16, true, 1, 16)), 53, 16);
    clean();
}

static void overlap_and_atomic() {
    auto first = fragment(0, 16, true);
    assert(submit(first).status == FragmentStatus::pending);
    auto atomic = fragment(0, 24, false);
    assert(submit(atomic).status == FragmentStatus::whole);
    assert(submit(first).status == FragmentStatus::duplicate);
    complete(submit(fragment(16, 37, false)));
    clean();
    for (unsigned variant = 0; variant < 4; variant++) {
        assert(submit(first).status == FragmentStatus::pending);
        auto overlap = variant == 0   ? fragment(8, 16, true)
                       : variant == 1 ? fragment(8, 8, true)
                                      : first;
        if (variant >= 2)
            overlap.back() ^= 1;
        assert(submit(overlap).status == FragmentStatus::rejected);
        assert(allocations.empty());
        clean();
    }
    assert(submit(first).status == FragmentStatus::pending);
    assert(submit(fragment(24, 8, false)).status == FragmentStatus::pending);
    assert(submit(fragment(32, 8, false)).status == FragmentStatus::rejected);
    clean();
}

static void bounds_and_headers() {
    auto result = submit(fragment(0, 9, true));
    assert(result.status == FragmentStatus::parameter_problem && result.error_pointer == 4);
    result = submit(fragment(65528, 8, false));
    assert(result.status == FragmentStatus::parameter_problem && result.error_pointer == 42);
    assert(submit(fragment(65528, 7, false)).status == FragmentStatus::pending);
    result = submit(fragment(0, 8, true, 1, 8));
    assert(result.status == FragmentStatus::parameter_problem && result.error_pointer == 50);
    assert(allocations.empty());
    assert(submit(fragment(0, 32760, true, 1, 0, 0, 17, 65535)).status == FragmentStatus::pending);
    auto large = submit(fragment(32760, 32775, false, 1, 0, 0, 17, 65535));
    assert(large.status == FragmentStatus::complete && large.length == 65575);
    auto decoded = decode(large.bytes, large.length);
    assert(decoded.length == 65535 && decoded.input == Input::payload);
    ax::release(large.bytes);
    clean();
    result = submit(fragment(0, 16, true, 1, 0, 0, 6));
    assert(result.status == FragmentStatus::parameter_problem && result.error_code == 3);
    auto tcp = fragment(0, 24, true, 1, 0, 0, 6);
    tcp[48 + 12] = 0x50;
    assert(submit(tcp).status == FragmentStatus::pending);
    clean();
    auto extension = fragment(0, 8, true, 1, 0, 0, 60);
    extension[48] = 17;
    extension[49] = 0;
    result = submit(extension);
    assert(result.status == FragmentStatus::parameter_problem && result.error_code == 3);
    extension = fragment(0, 16, true, 1, 0, 0, 60);
    std::fill(extension.begin() + 48, extension.begin() + 56, 0);
    extension[48] = 17;
    assert(submit(extension).status == FragmentStatus::pending);
    clean();
    auto first = fragment(0, 16, true);
    assert(submit(first).status == FragmentStatus::pending);
    first.back() ^= 1; // Admission owns its copy.
    complete(submit(fragment(16, 37, false)));
    clean();
    assert(submit(fragment(0, 16, true)).status == FragmentStatus::pending);
    assert(submit(fragment(8, 0, false)).status == FragmentStatus::rejected);
    assert(allocations.empty());
}

static void scope_ecn_and_resources() {
    assert(submit(fragment(0, 16, true), 1).status == FragmentStatus::pending);
    complete(submit(fragment(16, 37, false), 2));
    clean();
    auto a = fragment(0, 16, true), b = fragment(16, 37, false);
    a[24] = b[24] = 0xfe;
    a[25] = b[25] = 0x80;
    assert(submit(a, 1).status == FragmentStatus::pending);
    assert(submit(b, 2).status == FragmentStatus::pending);
    auto destination = decode(a.data(), a.size()).header.destination;
    reassembly_discard(&destination, 1);
    assert(!allocations.empty());
    reassembly_discard(&destination, 2);
    assert(allocations.empty());
    for (unsigned left = 0; left < 4; left++)
        for (unsigned right = 0; right < 4; right++) {
            assert(submit(fragment(0, 16, true, 1, 0, left)).status == FragmentStatus::pending);
            auto result = submit(fragment(16, 37, false, 1, 0, right));
            if ((left == 0) != (right == 0))
                assert(result.status == FragmentStatus::rejected);
            else
                complete(result, 53, 0, left == 3 || right == 3 ? 3 : left);
            clean();
        }
    for (unsigned id = 1; id <= reassembly_capacity; id++)
        assert(submit(fragment(16, 8, true, id)).status == FragmentStatus::pending);
    assert(submit(fragment(16, 8, true, 999)).status == FragmentStatus::exhausted);
    reassembly_expire(6099);
    assert(!allocations.empty());
    reassembly_expire(6100);
    assert(allocations.empty());
    for (int allowed = 0; allowed < 2; allowed++) {
        allowance = allowed;
        assert(submit(fragment(0, 16, true)).status == FragmentStatus::exhausted);
        assert(allocations.empty());
    }
    allowance = -1;
    assert(submit(fragment(0, 16, true)).status == FragmentStatus::pending);
    allowance = 0;
    assert(submit(fragment(16, 37, false)).status == FragmentStatus::exhausted);
    clean();
}

static void lifetime_and_malformed() {
    auto first = fragment(0, 16, true);
    assert(submit(first, 7, 100).status == FragmentStatus::pending);
    assert(submit(first, 7, 6000).status == FragmentStatus::duplicate);
    reassembly_expire(6099, expired);
    assert(quotes.empty());
    reassembly_expire(6100, expired);
    assert(quotes.size() == 1 && quotes[0] == first && quote_indices[0] == 7);
    assert(allocations.empty());
    clean();
    assert(submit(fragment(16, 8, true)).status == FragmentStatus::pending);
    reassembly_expire(6100, expired);
    assert(quotes.empty() && allocations.empty());
    std::mt19937 random(0x697036);
    for (unsigned n = 0; n < 4000; n++) {
        auto bytes = fragment((random() % 32) * 8, random() % 128, random() & 1, random() % 40);
        for (unsigned edit = 0; edit < 4; edit++)
            bytes[random() % bytes.size()] ^= uint8_t(random());
        auto result = reassemble(1, bytes.data(), random() % (bytes.size() + 1), n);
        if (result.bytes)
            ax::release(result.bytes);
        if (!(n % 64))
            clean();
    }
    clean();
}

int main() {
    ordering_and_prefixes();
    overlap_and_atomic();
    bounds_and_headers();
    scope_ecn_and_resources();
    lifetime_and_malformed();
    std::printf(
        "IPv6 reassembly: %u checks and 4000 malformed inputs passed; all allocations released\n",
        checks);
}
