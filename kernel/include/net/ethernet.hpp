// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "core/base.hpp"

namespace ax {
constexpr unsigned max_net_devices = 8;
constexpr size_t ethernet_header = 14, max_ethernet_frame = 65535 + 18;

struct NetStats {
    uint64_t rx_packets = 0, rx_bytes = 0, rx_dropped = 0, rx_errors = 0;
    uint64_t tx_packets = 0, tx_bytes = 0, tx_dropped = 0, tx_errors = 0;
};

struct NetInfo {
    unsigned index = 0;
    char name[16]{};
    uint8_t mac[6]{};
    uint32_t mtu = 1500, maximum_mtu = 1500;
    bool administrative = false, carrier = false, live = false, writable = false;
    NetStats stats;
};

// One CPU, serialized with interrupts masked. send copies the complete frame;
// a successful return transfers ownership to the adapter until TX completion.
// RX buffers belong to the adapter; net_receive copies them before returning.
struct NetAdapter {
    NetInfo info;
    void (*poll)(NetAdapter&);
    int (*send)(NetAdapter&, const void*, size_t);
    void (*stop)(NetAdapter&);
    void* data;
};

void net_init();

void net_poll();

void net_shutdown();

unsigned net_register(NetAdapter&);

const NetInfo* net_info(unsigned index);

int net_configure(unsigned index, bool administrative, uint32_t mtu);

bool net_writable(unsigned index);

int net_send(unsigned index, const void*, size_t, const void* sender = nullptr);

void net_receive(NetAdapter&, const void*, size_t);

void net_tx_complete(NetAdapter&, size_t, bool error = false);

void net_rx_error(NetAdapter&);
} // namespace ax
