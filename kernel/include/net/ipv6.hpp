// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "net/ethernet.hpp"
#include "net/ipv6/wire.hpp"

namespace ax {
struct Inet6Socket;
struct Ipv6Destination;
constexpr unsigned ipv6_address_capacity = 16, ipv6_route_capacity = 16;
constexpr unsigned ipv6_loopback = max_net_devices + 1;

// A captured source can outlive its interface address; fresh selection cannot.
enum class Ipv6SourcePolicy : uint8_t { assigned, retained };

struct Ipv6Address {
    ip6::Address address;
    unsigned index = 0;
    uint16_t flags = 0x80;
    uint8_t prefix = 128;
};

struct Ipv6AddressLifetimes {
    uint32_t preferred = UINT32_MAX, valid = UINT32_MAX;
};

struct Ipv6AddressCacheInfo {
    uint32_t preferred = UINT32_MAX, valid = UINT32_MAX;
    uint32_t created = 0, updated = 0;
};

static_assert(sizeof(Ipv6AddressLifetimes) == 8 && sizeof(Ipv6AddressCacheInfo) == 16);

struct Ipv6Route {
    ip6::Address destination, gateway;
    unsigned index = 0, metric = 1024;
    uint8_t prefix = 0, protocol = 3;
    uint64_t owner = 0;
    uint64_t expires = 0;
    int8_t preference = 0;
    bool learned = false;
};

struct Ipv6Path {
    ip6::Address source, next_hop;
    unsigned index = 0;
    uint32_t mtu = 0;
    uint64_t route_owner = 0;
    uint8_t route_prefix = 0;
};

// Serialized borrowers retain an entry only until the next address mutation.
const Ipv6Address* ipv6_address(unsigned position);

int ipv6_address_add(const Ipv6Address&, Ipv6AddressLifetimes = {}, bool replace = false);

Ipv6AddressCacheInfo ipv6_address_cache(const Ipv6Address&);

int ipv6_address_remove(unsigned index, const ip6::Address&);

bool ipv6_owned(unsigned index, const ip6::Address&, bool tentative = false);

int ipv6_route_control(const Ipv6Route&, bool remove, bool exclusive);

size_t ipv6_routes(Ipv6Route*, size_t capacity);

int ipv6_path(const ip6::Address& source, const ip6::Address& destination, unsigned bound_index,
              Ipv6Path&, bool interface_mtu = false, Ipv6SourcePolicy = Ipv6SourcePolicy::assigned);

void ipv6_mtu_changed(unsigned index, uint32_t previous);

// Success owns a copy until device acceptance or bounded resolution failure.
// A hop limit of -1 snapshots the selected outgoing interface's default.
int ipv6_send(const ip6::Address& source, const ip6::Address& destination, unsigned bound_index,
              uint8_t protocol, int16_t hop_limit, const void*, size_t,
              Inet6Socket* owner = nullptr, bool fragmentable = true, uint32_t socket_mtu = 0,
              bool interface_mtu = false, uint8_t traffic_class = 0,
              const ip6::OutputExtensions* extensions = nullptr,
              Ipv6SourcePolicy = Ipv6SourcePolicy::assigned);

// Copied transport output may outlive its description. With an owner, successful
// admission calls complete exactly once unless detached; failed admission never calls it.
// Completion may reenter output or detach another identity. Caller serializes access
// and keeps identity alive until completion or detach. Error is a negative errno.
struct Ipv6OutputOwner {
    void* identity = nullptr;
    void (*complete)(void*, size_t bytes, int error, unsigned output_index) = nullptr;
};

// Transport output uses the selected route/MTU without source fragmentation.
int ipv6_send_owned(Ipv6OutputOwner, const ip6::Address& source, const ip6::Address& destination,
                    unsigned bound_index, uint8_t protocol, int16_t hop_limit, const void*, size_t,
                    Ipv6SourcePolicy = Ipv6SourcePolicy::assigned, uint8_t traffic_class = 0,
                    Ipv6Destination* = nullptr);

// Retire superseded copied transport packets above this IPv6 path MTU.
// Each completion reports -ECANCELED, including deferred device submission.
void ipv6_discard_oversized(void* identity, uint32_t mtu);

// Detach callbacks only; admitted packet bytes retain their original bounded lifetime.
void ipv6_detach_output(void* identity);

bool ipv6_output_ready();

// Queued bytes outlive a closed socket, without callbacks to a reused slot.
void ipv6_detach_owner(Inet6Socket*);

void ipv6_receive(const NetInfo&, const void*, size_t);

void ipv6_poll();

void ipv6_shutdown();
} // namespace ax
