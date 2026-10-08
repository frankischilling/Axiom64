// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "net/ethernet.hpp"

namespace ax {
struct InetSocket;

// Addresses and masks in this interface are host-order IPv4 integers.
struct Ipv4Config {
    uint32_t address = 0, mask = 0xffffff00, broadcast = 0;
};

struct Ipv4Route {
    uint32_t destination = 0, mask = 0, gateway = 0;
    unsigned index = 0, metric = 0;
};

constexpr unsigned ipv4_loopback = max_net_devices + 1;

const Ipv4Config* ipv4_config(unsigned index);

int ipv4_configure(unsigned index, const Ipv4Config&);

int ipv4_route(const Ipv4Route&, bool remove);

bool ipv4_local(uint32_t address);

bool ipv4_output_ready();

int ipv4_source(uint32_t source, uint32_t destination, unsigned bound_index, uint32_t& selected);

int ipv4_send(InetSocket*, uint32_t source, uint32_t destination, unsigned bound_index,
              uint8_t protocol, uint8_t ttl, bool broadcast, const void*, size_t);

// Last socket close detaches error delivery; accepted packets own their bytes.
void ipv4_detach_owner(InetSocket*);

void ipv4_receive(const NetInfo&, const void*, size_t);

void ipv4_poll();

void ipv4_shutdown();
} // namespace ax
