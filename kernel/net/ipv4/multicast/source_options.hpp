// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "net/ipv4/multicast.hpp"

namespace ax {
struct Task;
struct Frame;
struct InetSocket;
using MulticastInterface = int (*)(unsigned, uint32_t, uint32_t, unsigned&);

// Linux x86-64 source-control layouts, ordered user copies and actual ownership
// updates. Resolution remains with the runtime that owns interfaces and routes.
int multicast_source_option(Task&, const Frame&, InetSocket*, ip4::MulticastHost&,
                            MulticastInterface, unsigned source_limit);
} // namespace ax
