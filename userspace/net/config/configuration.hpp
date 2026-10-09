// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "net/config/profile.hpp"
#include "net/config/routing.hpp"

namespace ax::dhcp {
struct Interface;
}

namespace ax::net {
// Owns only recorded address tuples and protocol-tagged routes. The runtime
// Store must outlive this object and live on a volatile filesystem. Opening
// recovers an earlier process's journal; final close leaves it for recovery.
// Positive errno results. Apply journals before mutation and rolls back failures.
class Configuration {
  public:
    Configuration() = default;

    ~Configuration();

    Configuration(const Configuration&) = delete;

    Configuration& operator=(const Configuration&) = delete;

    int open(const dhcp::Interface&, const Store& runtime);

    int close();

    int apply(uint32_t address, const dhcp::Parameters&, unsigned metric = 0,
              uint8_t protocol = 16);

    int withdraw();

  private:
    struct Snapshot {
        uint32_t address = 0, mask = 0, broadcast = 0;
        unsigned count = 0;
        Route routes[dhcp::max_routes + 1]{};
    };

    const Store* store_ = nullptr;
    int control_ = -1;
    char name_[16]{};
    unsigned index_ = 0;
    uint8_t mac_[6]{};
    Routing routing_;
    Snapshot active_, before_, after_;
    bool pending_ = false;

    int build(uint32_t, const dhcp::Parameters&, unsigned, uint8_t, Snapshot&) const;

    bool valid(const Snapshot&) const;

    int read_address(Snapshot&) const;

    int set_address(const Snapshot& old, const Snapshot& desired);

    int journal(const Snapshot&, const Snapshot&) const;

    int read_journal(Snapshot&, Snapshot&) const;

    int preflight(const Snapshot&, bool& unchanged);

    int mutate(const Route&, bool remove);

    int mutate(const Address&, bool remove);

    int remove_routes(const Snapshot&);

    int add_routes(const Snapshot&);

    int clear(const Snapshot&, const Snapshot&);

    int rollback(const Snapshot&, const Snapshot&);
};
} // namespace ax::net
