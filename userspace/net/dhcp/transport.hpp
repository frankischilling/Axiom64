// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "net/dhcp/state.hpp"
#include <poll.h>

namespace ax::dhcp {
struct Interface {
    char name[16]{};
    unsigned index = 0;
    Identity identity;
    bool up = false, carrier = false;
};

// Positive errno on failure; neither function changes interface configuration.
int query_interface(unsigned index, Interface&);

int query_address(const char* interface, uint32_t& address, uint32_t& mask);

enum class Received : uint8_t { empty, ignored, reply, conflict };

class Transport {
  public:
    Transport() = default;

    ~Transport();

    Transport(const Transport&) = delete;

    Transport& operator=(const Transport&) = delete;

    int open(const Interface&);

    void close();

    int configured(uint32_t address);

    int transmit(const Action&);

    int receive(uint32_t transaction, uint32_t candidate, bool probing, Reply&, Received&);

    int carrier(bool&);

    size_t descriptors(pollfd*, size_t) const;

  private:
    Interface interface_;
    int control_ = -1, packet_ = -1, broadcast_ = -1, unicast_ = -1;
    uint32_t address_ = 0;
    unsigned cursor_ = 0;
    uint8_t local_macs_[8][6]{};
    size_t local_count_ = 0;

    int udp(uint32_t address);
};
} // namespace ax::dhcp
