// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "core/base.hpp"
#include "net/ipv4.hpp"
#include "net/ipv4/receive.hpp"
#include "net/ipv4/options.hpp"

namespace ax {
struct Task;
struct InetSocket;
struct Ipv4Destination;

struct InetAddress {
    uint16_t family, port;
    uint32_t address;
    uint8_t padding[8];
};

static_assert(sizeof(InetAddress) == 16);

struct InetSendControl {
    Ipv4Source source;
    unsigned index = 0;
    uint8_t ttl = 64, tos = 0;
    bool cache_destination = false;
    Ipv4SendRoute route{};
    ip4::Options options{};
};

struct InetFrame {
    InetAddress source;
    size_t length;
    Ipv4ReceiveMetadata metadata;
    bool packet_info_prepared;
};

inline const uint8_t* inet_bytes(const InetFrame* frame) {
    return reinterpret_cast<const uint8_t*>(frame + 1);
}

void inet_close(InetSocket*);

// Borrow only destination state that this output lookup may replace or clear.
// Raw output preserves failed lookups and refreshes only an existing cache.
Ipv4Destination* inet_output_destination(InetSocket*, uint32_t address, bool lookup_failed);

bool inet_payload(InetSocket*);

bool inet_dont_fragment(const InetSocket*, bool path_locked = false);

bool inet_fragmentation_allowed(const InetSocket*);

bool inet_use_path_mtu(const InetSocket*);
uint8_t inet_traffic_class(const InetSocket*);

bool inet_accept_path_mtu(const InetSocket*);

bool inet_ready(InetSocket*, bool write);

const InetFrame* inet_front(InetSocket*);

void inet_consume(InetSocket*);

InetAddress inet_peer(InetSocket*);

int inet_target(InetSocket*, InetAddress&, bool named);

unsigned inet_shutdown(InetSocket*);

size_t inet_available(InetSocket*);

int inet_error(InetSocket*, bool clear = false);

// An output error carries its failed device; zero identifies other diagnostics.
void inet_failed(InetSocket*, int error, unsigned failed_index = 0);

void inet_icmp_error(unsigned index, const uint8_t* quote, int error, uint16_t announced_mtu = 0);

void inet_reclaim(InetSocket*, size_t length);

// An eligible raw listener suppresses protocol-unreachable errors.
bool inet_deliver(const Ipv4ReceiveMetadata&, const void*, size_t);

bool inet_datagram_deliver(const Ipv4ReceiveMetadata&, uint16_t source_port,
                           uint16_t destination_port, bool broadcast, const void*, size_t);

size_t inet_receive_control(Task&, InetSocket*, const InetFrame&, uint64_t address,
                            uint64_t capacity, uint32_t& flags);

int inet_capture_send_control(Task&, uint64_t pointer, uint64_t length, uint8_t*& bytes);

int inet_prepare_send(InetSocket*, InetAddress&, bool named, uint32_t address_length,
                      size_t payload_length, const uint8_t* control, size_t control_length,
                      InetSendControl&, bool net_raw = false);

size_t inet_send_prefix(const InetSocket*);

int inet_send_admit(InetSocket*, InetAddress&, size_t, InetSendControl&);
int inet_send_ready(InetSocket*, size_t, const InetSendControl* = nullptr);

int64_t inet_send(InetSocket*, const InetAddress&, const void*, size_t, bool named = false,
                  const InetSendControl* control = nullptr);

int64_t inet_read(InetSocket*, void*, size_t);

int64_t inet_syscall(Task&, const Frame&);
} // namespace ax
