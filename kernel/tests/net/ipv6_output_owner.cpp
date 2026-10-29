// SPDX-License-Identifier: GPL-3.0-or-later
#include "net/ipv6.hpp"
#include "core/time.hpp"
#include <cassert>
#include <cstdio>
#include <array>
#include <vector>

const std::vector<std::vector<uint8_t>>& ipv6_emitted(unsigned lane);
void ipv6_test_budget(unsigned value);
void ipv6_test_cancel_on_poll(void*, unsigned polls, void (*probe)(void*));

namespace {
struct Owner {
    unsigned completions = 0, index = 0;
    size_t bytes = 0;
    int error = 0;
    Owner* detach = nullptr;

    ax::Ipv6OutputOwner output() {
        return {this, [](void* context, size_t size, int failure, unsigned egress) {
                    auto& owner = *static_cast<Owner*>(context);
                    owner.completions++;
                    owner.bytes += size;
                    owner.error = failure;
                    owner.index = egress;
                    if (owner.detach)
                        ax::ipv6_detach_output(owner.detach);
                }};
    }
};
} // namespace

void ipv6_output_owner_tests(void (*reset)()) {
    using namespace ax;
    reset();
    ip6::Address loop;
    loop.bytes[15] = 1;
    uint8_t data[20]{};
    Owner owner;
    assert(ipv6_send_owned(owner.output(), loop, loop, 0, 6, 256, data, sizeof(data)) == -22);
    assert(ipv6_send_owned({&owner, nullptr}, loop, loop, 0, 6, 64, data, sizeof(data)) == -22);
    auto broken = owner.output();
    broken.identity = nullptr;
    assert(ipv6_send_owned(broken, loop, loop, 0, 6, 64, data, sizeof(data)) == -22);
    assert(!owner.completions);

    assert(!ipv6_send_owned(owner.output(), loop, loop, 0, 6, 64, data, sizeof(data)));
    assert(!owner.completions);
    ipv6_poll();
    assert(owner.completions == 1 && owner.bytes == 60 && !owner.error &&
           owner.index == ipv6_loopback);
    ipv6_poll();
    assert(owner.completions == 1);

    // Superseded TCP copies complete once with cancellation, not device success.
    Owner superseded;
    uint8_t superseded_bytes[1400]{};
    assert(!ipv6_send_owned(superseded.output(), loop, loop, 0, 6, 64, superseded_bytes,
                            sizeof(superseded_bytes)));
    ipv6_discard_oversized(&superseded, 1279);
    assert(!superseded.completions);
    ipv6_discard_oversized(&superseded, 1280);
    assert(superseded.completions == 1 && superseded.error == -125 && superseded.bytes == 1440 &&
           superseded.index == ipv6_loopback);
    ipv6_discard_oversized(&superseded, 1280);
    ipv6_poll();
    assert(superseded.completions == 1 && ipv6_output_ready());

    // Retiring an identity preserves queued bytes but removes every late callback.
    Owner retired;
    for (unsigned at = 0; at < 32; at++)
        assert(!ipv6_send_owned(retired.output(), loop, loop, 0, 6, 64, data, sizeof(data)));
    assert(ipv6_send_owned(owner.output(), loop, loop, 0, 6, 64, data, sizeof(data)) == -11);
    assert(owner.completions == 1);
    ipv6_detach_output(&retired);
    ipv6_poll();
    assert(!retired.completions && ipv6_output_ready());
    assert(!ipv6_send_owned(retired.output(), loop, loop, 0, 6, 64, data, sizeof(data)));
    ipv6_poll();
    assert(retired.completions == 1 && retired.bytes == 60);

    Owner first, second;
    first.detach = &second;
    assert(!ipv6_send_owned(first.output(), loop, loop, 0, 6, 64, data, sizeof(data)));
    assert(!ipv6_send_owned(second.output(), loop, loop, 0, 6, 64, data, sizeof(data)));
    ipv6_poll();
    assert(first.completions == 1 && !second.completions);

    Owner stopped;
    for (unsigned at = 0; at < 3; at++)
        assert(!ipv6_send_owned(stopped.output(), loop, loop, 0, 6, 64, data, sizeof(data)));
    ipv6_shutdown();
    assert(stopped.completions == 3 && stopped.error == -5 && stopped.bytes == 180 &&
           stopped.index == ipv6_loopback);
    ipv6_shutdown();
    assert(stopped.completions == 3);
    reset();
    ip6::Address local{{0x20, 0x01, 0x0d, 0xb8, 1}};
    local.bytes[15] = 2;
    auto remote = local;
    remote.bytes[15] = 1;
    ip6::Address multicast{{0xff, 2}};
    multicast.bytes[15] = 1;
    assert(!ipv6_address_add({local, 1, 0x82, 64}));
    assert(!ipv6_route_control({{}, {}, 1, 1024, 0}, false, true));
    Owner physical;
    memset(data, 0x71, sizeof(data));
    assert(!ipv6_send_owned(physical.output(), local, multicast, 1, 6, 64, data, sizeof(data)));
    memset(data, 0xd3, sizeof(data));
    size_t before = ipv6_emitted(0).size();
    ipv6_poll();
    assert(physical.completions == 1 && !physical.error && physical.index == 1 &&
           physical.bytes == 60 && ipv6_emitted(0).size() > before);
    const auto& frame = ipv6_emitted(0).back();
    assert(frame.size() == 74);
    for (unsigned at = 54; at < frame.size(); at++)
        assert(frame[at] == 0x71);

    std::array<uint8_t, 1461> large{};
    Owner in_submission;
    before = ipv6_emitted(0).size();
    assert(
        !ipv6_send_owned(in_submission.output(), local, multicast, 1, 6, 64, large.data(), 1460));
    ipv6_test_cancel_on_poll(&in_submission, 1, [](void* identity) {
        // The device still borrows the packet; completion must wait for return.
        assert(!static_cast<Owner*>(identity)->completions);
    });
    ipv6_poll();
    assert(in_submission.completions == 1 && in_submission.error == -125 &&
           in_submission.bytes == 1500 && in_submission.index == 1 &&
           ipv6_emitted(0).size() == before && ipv6_output_ready());
    ipv6_poll();
    assert(in_submission.completions == 1);

    Owner oversized;
    assert(ipv6_send_owned(oversized.output(), local, multicast, 1, 6, 64, large.data(),
                           large.size()) == -90);
    assert(!oversized.completions);
    // A packet admitted before a route's MTU change fails its owner exactly once.
    ipv6_test_budget(0);
    assert(!ipv6_send_owned(oversized.output(), local, multicast, 1, 6, 64, large.data(), 1460));
    ipv6_poll();
    assert(!oversized.completions);
    assert(!net_configure(1, true, 1280));
    ipv6_test_budget(UINT32_MAX);
    before = ipv6_emitted(0).size();
    ipv6_poll();
    assert(oversized.completions == 1 && oversized.error == -90 && oversized.index == 1 &&
           oversized.bytes == 1500 && ipv6_emitted(0).size() == before);

    Owner expired;
    assert(!ipv6_send_owned(expired.output(), local, remote, 0, 6, 64, data, sizeof(data)));
    ticks += 400;
    ipv6_poll();
    assert(expired.completions == 1 && expired.error == -113 && expired.index == 1 &&
           expired.bytes == 60);
    ipv6_poll();
    assert(expired.completions == 1);

    Owner rerouted;
    assert(!ipv6_send_owned(rerouted.output(), local, remote, 0, 6, 64, data, sizeof(data)));
    assert(!ipv6_route_control({remote, {}, 2, 1024, 128}, false, true));
    ipv6_poll();
    assert(!rerouted.completions);
    ticks += 400;
    ipv6_poll();
    assert(rerouted.completions == 1 && rerouted.error == -113 && rerouted.index == 2);
    reset();
    std::puts(
        "IPV6_OUTPUT_OWNER_PASS admission completion errno egress capacity detach reuse "
        "reentrant_detach reentrant_cancel shutdown physical_copy mtu_shrink expiry reroute once");
}
