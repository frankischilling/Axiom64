// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "net/ipv4/multicast.hpp"

namespace ax {
struct InetSocket;
struct Task;
struct Frame;
bool ipv4_multicast_member(unsigned index, uint32_t group);
bool inet_multicast_accepts(const InetSocket*, unsigned index, uint32_t group);
void inet_multicast_close(InetSocket*);
bool inet_multicast_loop(const InetSocket*);
int inet_multicast_option(Task&, const Frame&, InetSocket*);
void ipv4_multicast_poll();
void ipv4_multicast_input(unsigned index, const uint8_t*, size_t);
// Queue a complete owned IGMP frame with Router Alert; never transmits inline.
bool ipv4_multicast_report(unsigned index, uint32_t destination, const uint8_t*, size_t);
} // namespace ax
