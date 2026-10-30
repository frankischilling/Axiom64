// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "net/ethernet.hpp"

namespace ax {
bool ipv4_option_unicast(uint32_t address, void* context);
struct InetSocket;

namespace ip4 {
class Options;
}

// Addresses and masks in this interface are host-order IPv4 integers.
struct Ipv4Config {
    uint32_t address = 0, mask = 0xffffff00, broadcast = 0;
};

constexpr unsigned ipv4_address_capacity = 32;

struct Ipv4Address {
    Ipv4Config config;
    unsigned index = 0;
    char label[16]{};
    bool secondary = false;
};

struct Ipv4Route {
    uint32_t destination = 0, mask = 0, gateway = 0;
    unsigned index = 0, metric = 0;
    uint8_t protocol = 3, scope = 255;
    // Listing metadata; mutation requests select their source independently.
    uint32_t preferred_source = 0;
};

constexpr unsigned ipv4_loopback = max_net_devices + 1;

const Ipv4Config* ipv4_config(unsigned index);

// Serialized callers may borrow entries until the next address mutation.
const Ipv4Address* ipv4_address(unsigned position);

const Ipv4Config* ipv4_label(unsigned index, const char* label, uint32_t hint = 0);

int ipv4_configure(unsigned index, const Ipv4Config&);

int ipv4_configure_label(unsigned index, const char* label, const Ipv4Config&);

int ipv4_address_add(unsigned index, const char* label, const Ipv4Config&);

int ipv4_address_remove(unsigned index, uint32_t address, uint32_t mask);

// A changed link MTU adjusts that interface's exceptions without renewing expiry.
void ipv4_mtu_changed(unsigned index, uint32_t previous_mtu);

// Administrative transitions retire device routes and queued local output.
int ipv4_administrative_changed(unsigned index);

int ipv4_route(const Ipv4Route&, bool remove);

// Routing control retains protocol/scope and applies Linux deletion filters.
int ipv4_route_control(const Ipv4Route&, bool remove, bool exclusive);

size_t ipv4_routes(Ipv4Route*, size_t capacity);

bool ipv4_local(uint32_t address);

bool ipv4_output_ready();

// Zero requests selection unless the description retained it as its actual source.
struct Ipv4Source {
    uint32_t address;
    bool selected;

    constexpr Ipv4Source(uint32_t value = 0) : address(value), selected(value != 0) {
    }

    static constexpr Ipv4Source retained(uint32_t value) {
        Ipv4Source source{value};
        source.selected = true;
        return source;
    }
};

struct Ipv4Path {
    uint32_t source, mtu;
    unsigned index;
};

int ipv4_path(Ipv4Source source, uint32_t destination, unsigned bound_index, Ipv4Path&);

// A socket owns its selected destination even when a later route edit retires it.
struct Ipv4Destination {
    Ipv4Path path{};
    // Route refresh uses the description's lookup source, independent of wire output.
    uint32_t address = 0, source = 0;
    unsigned bound_index = 0;
    uint64_t generation = 0, expires = 0;
    bool local = false, gateway = false, locked = false;
};

int ipv4_destination(Ipv4Destination&, Ipv4Source source, uint32_t destination,
                     unsigned bound_index);

bool ipv4_destination_current(const Ipv4Destination&);

// Datagram/raw getters return the retained value before refreshing obsolete state.
int ipv4_destination_mtu(Ipv4Destination&, bool refresh_route);

void ipv4_destination_release(Ipv4Destination&);

// A validated transport quote may lower the selected path. Zero means no eligible route.
uint32_t ipv4_learn_pmtu(uint32_t source, uint32_t destination, unsigned index,
                         uint16_t announced_mtu, uint16_t quoted_length);

int ipv4_source(Ipv4Source source, uint32_t destination, unsigned bound_index, uint32_t& selected);

// A retained send owns these route values through its memory wait. Later
// address and route edits affect later calls without selecting this packet again.
// Retirement of its last next-hop owner silently consumes the held send.
struct Ipv4SendRoute {
    Ipv4Path path{};
    uint32_t destination = 0, next_hop = 0, path_source = 0;
    uint64_t path_owner = 0;
    bool local = false, broadcast = false, locked = false;
};

// Positive output consumption has no queued buffer to charge to the socket.
constexpr int ipv4_output_discarded = 1;

int ipv4_send(InetSocket*, Ipv4Source source, uint32_t destination, unsigned bound_index,
              uint8_t protocol, uint8_t ttl, bool broadcast, const void*, size_t,
              bool cache_destination = true, int traffic_class = -1,
              const Ipv4SendRoute* selected = nullptr, const ip4::Options* options = nullptr);

int ipv4_send_admit(InetSocket*, Ipv4Source source, uint32_t destination, unsigned bound_index,
                    uint8_t ttl, bool broadcast, size_t length, bool cache_destination,
                    Ipv4SendRoute* selected = nullptr, const ip4::Options* options = nullptr);

// Literal header output uses the message destination for routing. Its complete
// packet must fit the device MTU and is never fragmented or recompiled as options.
int ipv4_send_header_admit(InetSocket*, Ipv4Source, uint32_t destination, unsigned bound_index,
                           bool broadcast, size_t length, bool cache_destination,
                           Ipv4SendRoute* selected);
int ipv4_send_header(InetSocket*, Ipv4Source, uint32_t destination, unsigned bound_index,
                     bool broadcast, const void*, size_t, bool cache_destination,
                     const Ipv4SendRoute* selected = nullptr);

// Last socket close detaches error delivery; accepted packets own their bytes.
void ipv4_detach_owner(InetSocket*);
// Release only oversized queued copies; the transport retains its original bytes.
void ipv4_discard_oversized(InetSocket*, uint16_t mtu);

void ipv4_receive(const NetInfo&, const void*, size_t);

void ipv4_poll();

void ipv4_shutdown();
} // namespace ax
