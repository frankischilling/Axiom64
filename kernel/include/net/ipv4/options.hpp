// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <cstddef>
#include <cstdint>

namespace ax::ip4 {
struct OptionPolicy {
    bool net_raw = false;
    bool (*unicast_address)(uint32_t, void*) = nullptr;
    bool (*security_label)(const uint8_t*, size_t, void*) = nullptr;
    void* context = nullptr;
};

// A description owns its normalized query value. Copies retain the chosen
// record/timestamp slots independently of later option or address changes.
class Options {
  public:
    static constexpr size_t capacity = 40;

    // A failed assignment preserves the entire preceding value. Empty input clears
    // it without reading data; output padding uses End of Option List bytes.
    int assign(const uint8_t* data, size_t length, const OptionPolicy& = {});

    const uint8_t* data() const {
        return bytes_;
    }

    size_t size() const {
        return size_ & 0x7f;
    }

    // Linux retains an allocated option value even after an explicit empty set.
    // Header-included sends reject that value independently of its wire length.
    bool assigned() const {
        return size_ != 0;
    }

    bool source_route() const {
        return route_ != absent;
    }

    bool strict_route() const {
        return source_route() && bytes_[route_] == 137;
    }

    uint32_t destination(uint32_t final_destination) const {
        return source_route() ? first_hop_ : final_destination;
    }

    // Output owns its bytes before it can wait. The route's interface source
    // supplies recorded addresses; the caller supplies actual UTC milliseconds
    // since midnight. A short output leaves its destination unchanged.
    int emit(uint8_t* output, size_t available, uint32_t final_destination, uint32_t route_source,
             uint32_t timestamp) const;

  private:
    friend class ReceivedOptions;
    static constexpr uint8_t absent = 255;
    uint8_t bytes_[capacity]{};
    uint8_t size_ = 0, route_ = absent, record_ = absent, record_pointer_ = absent;
    uint8_t time_ = absent, time_address_ = absent, time_pointer_ = absent, time_advance_ = 0;
    uint32_t first_hop_ = 0;
};

// A packet owns its processed input and independently prepared return value.
// Syntax errors identify the offending byte in the complete IPv4 header.
// Source-route admission and forwarding remain routing policy decisions.
class ReceivedOptions {
  public:
    int assign(const uint8_t*, size_t, uint32_t source, uint32_t specific_destination,
               uint32_t timestamp, const OptionPolicy& = {});

    const uint8_t* data() const {
        return bytes_;
    }

    size_t size() const {
        return size_;
    }

    uint8_t parameter() const {
        return parameter_;
    }

    bool source_route() const {
        return route_ != 255;
    }

    bool strict_route() const {
        return source_route() && bytes_[route_] == 137;
    }

    // Walk only locally addressed hops. A remote hop stays unconsumed until
    // forwarding owns an egress route. Return 1 for that hop, 0 when exhausted,
    // or -EINVAL with parameter() identifying an incomplete address slot.
    int route(uint32_t& destination, uint32_t& next_hop, bool (*local)(uint32_t));

    // Rewrite the slot selected by route(), plus recorded egress addresses.
    // Receive timestamps and already visited source-route slots stay unchanged.
    void forward(uint32_t egress_source);

    bool return_valid() const {
        return return_valid_;
    }

    const Options& reply() const {
        return reply_;
    }

  private:
    uint8_t bytes_[40]{};
    uint8_t size_ = 0, parameter_ = 0, route_ = 255;
    uint8_t pending_route_ = 255, recorded_address_ = 255, timestamp_address_ = 255;
    bool return_valid_ = true;
    Options reply_{};
};
} // namespace ax::ip4
