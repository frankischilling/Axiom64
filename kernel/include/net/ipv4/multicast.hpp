// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "net/ipv4/source_filter.hpp"
#include "net/ipv4/source_reports.hpp"
#include <cstddef>
#include <cstdint>

namespace ax::ip4 {
constexpr bool multicast(uint32_t address) {
    return (address >> 28) == 14;
}

struct MulticastMembership {
    struct Entry {
        uint32_t group = 0;
        unsigned index = 0;
        MulticastSourceFilter filter;
    };

    static constexpr unsigned capacity = 20;
    Entry entries[capacity]{};
    unsigned output_index = 0;
    uint32_t output_address = 0;
    uint8_t ttl = 1;
    bool loop = true, all = true;
};

// Serialized by the network poll/syscall execution model. Entries belong to a
// socket description, not a descriptor; only final close releases its interests.
// Timers use the kernel's 100 Hz ticks. Poll consumes a report only after emit
// accepts it. No socket operation sends recursively through an RX callback.
class MulticastHost {
  public:
    static constexpr unsigned group_capacity = 128, interface_capacity = 16;
    using Emit = bool (*)(void*, unsigned, uint32_t, const uint8_t*, size_t);

    void seed(uint32_t);
    int join(MulticastMembership&, unsigned index, uint32_t group, uint64_t now);
    int leave(MulticastMembership&, unsigned index, uint32_t group, uint64_t now);
    int source(MulticastMembership&, unsigned index, uint32_t group, unsigned mode, bool add,
               uint32_t address, unsigned limit, uint64_t now);
    int replace(MulticastMembership&, unsigned index, uint32_t group, unsigned mode,
                const uint32_t* addresses, unsigned count, unsigned limit, uint64_t now);
    const MulticastSourceFilter* filter(const MulticastMembership&, unsigned index,
                                        uint32_t group) const;
    void close(MulticastMembership&, uint64_t now);
    bool member(unsigned index, uint32_t group) const;
    bool accepts_source(unsigned index, uint32_t group, uint32_t source) const;
    bool accepts(const MulticastMembership&, unsigned index, uint32_t group,
                 uint32_t source = 0) const;
    void link(unsigned index, bool up, uint64_t now, uint32_t mtu = 68);
    void receive(unsigned index, uint32_t destination, const uint8_t*, size_t, bool router_alert,
                 uint64_t now);
    void poll(uint64_t now, Emit, void*);

  private:
    struct Group {
        uint32_t address = 0;
        unsigned index = 0, remaining = 0;
        MulticastSourceAggregate interest;
        MulticastSourceReports reports;
        uint64_t change = 0, response = 0;
        uint32_t sources[64]{};
        unsigned source_count = 0, response_cursor = 0;
        bool last_reporter = false;
    };

    struct Link {
        bool up = false;
        unsigned robustness = 2, selected = 3;
        uint32_t mtu = 68;
        uint64_t query_interval = 12500, response_interval = 1000;
        uint64_t v1_until = 0, v2_until = 0;
    };

    Group groups[group_capacity]{};
    Link links[interface_capacity]{};
    uint32_t random_state = 0x4158494f;
    Group* find(unsigned, uint32_t);
    uint64_t delay(uint64_t);
    unsigned version(unsigned index, uint64_t now) const;
    void synchronize(unsigned index, uint64_t now);
    void changed(Group&, bool previously_present, uint64_t now);
    bool respond(Group&, unsigned max_sources, Emit, void*);
    int commit(MulticastMembership::Entry&, unsigned index, uint32_t group,
               const MulticastSourceFilter&, uint64_t now);
};
} // namespace ax::ip4
