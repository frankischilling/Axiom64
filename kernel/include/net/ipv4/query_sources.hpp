// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <cstddef>
#include <cstdint>

namespace ax::ip4 {
struct MulticastQueryBudget {
    size_t limit = 262144;
    size_t used = 0;
};

// A pending source query owns a sorted unique set, independent of the socket
// filter's capacity. The budget outlives every set using it. Serialized callers
// can merge complete validated wire lists; refusal preserves the previous set.
class MulticastQuerySources {
  public:
    MulticastQuerySources() = default;
    MulticastQuerySources(const MulticastQuerySources&) = delete;
    MulticastQuerySources& operator=(const MulticastQuerySources&) = delete;
    MulticastQuerySources(MulticastQuerySources&&);
    MulticastQuerySources& operator=(MulticastQuerySources&&);
    ~MulticastQuerySources();

    bool merge(const uint8_t* addresses, unsigned count, MulticastQueryBudget&);
    void clear();

    unsigned size() const {
        return count;
    }

    const uint32_t* data() const {
        return addresses;
    }

  private:
    MulticastQueryBudget* budget = nullptr;
    uint32_t* addresses = nullptr;
    size_t allocated = 0;
    unsigned count = 0;
    bool contains(uint32_t) const;
};
} // namespace ax::ip4
