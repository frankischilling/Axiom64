// SPDX-License-Identifier: GPL-3.0-or-later
#include "net/ipv4/options.hpp"
#include "net/ipv4_wire.hpp"
#include "core/base.hpp"

namespace ax::ip4 {
namespace {
bool remote_unicast(uint32_t address, const OptionPolicy& policy) {
    if (policy.unicast_address)
        return policy.unicast_address(address, policy.context);
    return (address >> 24) && (address >> 24) != 127 && (address >> 28) != 14 &&
           address != UINT32_MAX;
}
} // namespace

int Options::assign(const uint8_t* data, size_t length, const OptionPolicy& policy) {
    if (length > capacity || (length && !data))
        return -22;
    Options next;
    next.size_ = uint8_t((length + 3) & ~size_t(3));
    if (length)
        memcpy(next.bytes_, data, length);
    bool record_seen = false, time_seen = false, route_seen = false, label_seen = false;
    for (size_t at = 0; at < next.size_;) {
        auto option = next.bytes_ + at;
        const uint8_t type = option[0];
        if (!type) {
            memset(option, 0, next.size_ - at);
            break;
        }
        if (type == 1) {
            at++;
            continue;
        }
        if (next.size_ - at < 2 || option[1] < 2 || option[1] > next.size_ - at)
            return -22;
        const unsigned size = option[1];
        if (type == 131 || type == 137) {
            if (route_seen || size < 7 || (size - 3) % 4 || option[2] != 4)
                return -22;
            route_seen = true;
            next.route_ = uint8_t(at);
            next.first_hop_ = get32(option + 3);
        } else if (type == 7) {
            if (record_seen || size < 3 || option[2] < 4)
                return -22;
            record_seen = true;
            const unsigned pointer = option[2];
            if (pointer <= size) {
                if (size - pointer < 3)
                    return -22;
                next.record_ = uint8_t(at + pointer - 1);
                next.record_pointer_ = uint8_t(at + 2);
                memset(next.bytes_ + next.record_, 0, 4);
            }
        } else if (type == 68) {
            if (time_seen || size < 4 || option[2] < 5)
                return -22;
            time_seen = true;
            const unsigned pointer = option[2], mode = option[3] & 15;
            if (pointer <= size) {
                if (size - pointer < 3)
                    return -22;
                if (mode == 0) {
                    next.time_ = uint8_t(at + pointer - 1);
                    next.time_advance_ = 4;
                } else if (mode == 1 || mode == 3) {
                    if (size - pointer < 7)
                        return -22;
                    if (mode == 1 || !remote_unicast(get32(option + pointer - 1), policy)) {
                        next.time_ = uint8_t(at + pointer + 3);
                        next.time_advance_ = 8;
                        if (mode == 1) {
                            next.time_address_ = uint8_t(at + pointer - 1);
                            memset(next.bytes_ + next.time_address_, 0, 4);
                        }
                    }
                } else if (!policy.net_raw)
                    return -22;
                if (next.time_ != absent) {
                    next.time_pointer_ = uint8_t(at + 2);
                    memset(next.bytes_ + next.time_, 0, 4);
                }
            } else if (mode != 3 && (option[3] >> 4) == 15)
                return -22;
        } else if (type == 148) {
            if (size < 4)
                return -22;
        } else if (type == 134) {
            // A label requires an installed security policy. Unknown domains
            // remain rejected rather than being accepted as opaque options.
            if (!policy.net_raw || label_seen || !policy.security_label ||
                !policy.security_label(option, size, policy.context))
                return -22;
            label_seen = true;
        } else if (!policy.net_raw)
            return -22;
        at += size;
    }
    if (next.source_route() && !policy.net_raw)
        return -1;
    *this = next;
    return 0;
}

int Options::emit(uint8_t* output, size_t available, uint32_t final_destination,
                  uint32_t route_source, uint32_t timestamp) const {
    if (available < size_)
        return -105;
    if (size_ && !output)
        return -22;
    if (!size_)
        return 0;
    memcpy(output, bytes_, size_);
    if (source_route()) {
        const unsigned length = bytes_[route_ + 1];
        for (unsigned index = 3; index + 4 < length; index++)
            output[route_ + index] = bytes_[route_ + index + 4];
        put32(output + route_ + length - 4, final_destination);
    }
    if (record_ != absent) {
        output[record_pointer_] += 4;
        put32(output + record_, route_source);
    }
    if (time_ != absent) {
        output[time_pointer_] += time_advance_;
        put32(output + time_, timestamp);
    }
    if (time_address_ != absent)
        put32(output + time_address_, route_source);
    return size_;
}

int ReceivedOptions::assign(const uint8_t* data, size_t length, uint32_t source,
                            uint32_t specific_destination, uint32_t timestamp,
                            const OptionPolicy& policy) {
    *this = {};
    if (length > 40 || (length & 3) || (length && !data))
        return -22;
    size_ = uint8_t(length);
    if (length)
        memcpy(bytes_, data, length);
    uint8_t record = 255, time = 255, label = 255;
    bool recorded = false, timed = false, addressed = false;
    auto invalid = [&](size_t at) {
        parameter_ = uint8_t(20 + at);
        return -22;
    };
    for (size_t at = 0; at < length;) {
        auto option = bytes_ + at;
        uint8_t type = *option;
        if (!type) {
            memset(option, 0, length - at);
            break;
        }
        if (type == 1) {
            at++;
            continue;
        }
        if (length - at < 2 || option[1] < 2 || option[1] > length - at)
            return invalid(at);
        unsigned size = option[1];
        if (type == 131 || type == 137 || type == 7) {
            if (type == 7 && record != 255)
                return invalid(at);
            if (size < 3)
                return invalid(at + 1);
            if (option[2] < 4)
                return invalid(at + 2);
            auto& offset = type == 7 ? record : route_;
            if (offset != 255)
                return invalid(at);
            offset = uint8_t(at);
            if (type == 7 && option[2] <= size) {
                if (unsigned(option[2]) + 3 > size)
                    return invalid(at + 2);
                put32(option + option[2] - 1, specific_destination);
                option[2] += 4;
                recorded = true;
            }
        } else if (type == 68) {
            if (time != 255)
                return invalid(at);
            if (size < 4)
                return invalid(at + 1);
            if (option[2] < 5)
                return invalid(at + 2);
            time = uint8_t(at);
            unsigned pointer = option[2], mode = option[3] & 15;
            if (pointer <= size) {
                if (pointer + 3 > size)
                    return invalid(at + 2);
                if (mode == 0) {
                    put32(option + pointer - 1, timestamp);
                    option[2] += 4;
                    timed = true;
                } else if (mode == 1 || mode == 3) {
                    if (pointer + 7 > size)
                        return invalid(at + 2);
                    if (mode == 1 || !remote_unicast(get32(option + pointer - 1), policy)) {
                        if (mode == 1) {
                            put32(option + pointer - 1, specific_destination);
                            addressed = true;
                        }
                        put32(option + pointer + 3, timestamp);
                        option[2] += 8;
                        timed = true;
                    }
                }
            } else if (mode != 3) {
                if ((option[3] >> 4) == 15)
                    return invalid(at + 3);
                option[3] += 16;
            }
        } else if (type == 148) {
            if (size < 4)
                return invalid(at + 1);
        } else if (type == 134) {
            if (label != 255)
                return invalid(at);
            if (!policy.security_label || !policy.security_label(option, size, policy.context))
                return invalid(at);
            label = uint8_t(at);
        }
        at += size;
    }

    auto append = [&](uint8_t offset) {
        unsigned begin = reply_.size_, size = bytes_[offset + 1];
        memcpy(reply_.bytes_ + begin, bytes_ + offset, size);
        reply_.size_ += uint8_t(size);
        return begin;
    };
    if (record != 255) {
        unsigned begin = append(record), size = bytes_[record + 1];
        unsigned pointer = bytes_[record + 2];
        if (recorded && pointer <= size) {
            if (pointer + 3 > size)
                return_valid_ = false;
            else {
                reply_.record_ = uint8_t(begin + pointer - 1);
                reply_.record_pointer_ = uint8_t(begin + 2);
                memset(reply_.bytes_ + reply_.record_, 0, 4);
            }
        }
    }
    if (time != 255) {
        unsigned begin = append(time), size = bytes_[time + 1];
        unsigned pointer = bytes_[time + 2], mode = bytes_[time + 3] & 15;
        if (pointer <= size && timed) {
            unsigned advance = addressed ? 8 : mode == 3 ? 8 : 4;
            bool reserve =
                mode != 3 || (pointer + 7 <= size &&
                              !remote_unicast(get32(bytes_ + time + pointer - 1), policy));
            if (reserve && pointer + advance - 1 > size)
                return_valid_ = false;
            else if (reserve) {
                if (addressed) {
                    reply_.time_address_ = uint8_t(begin + pointer - 1);
                    memset(reply_.bytes_ + reply_.time_address_, 0, 4);
                }
                reply_.time_ = uint8_t(begin + pointer - 1 + (advance == 8 ? 4 : 0));
                reply_.time_pointer_ = uint8_t(begin + 2);
                reply_.time_advance_ = uint8_t(advance);
                memset(reply_.bytes_ + reply_.time_, 0, 4);
            }
        }
    }
    if (route_ != 255) {
        auto option = bytes_ + route_;
        int cursor = min(int(option[2]), int(option[1]) + 1) - 4;
        uint32_t visited[10]{};
        unsigned count = 0;
        for (; cursor > 3; cursor -= 4)
            visited[count++] = get32(option + cursor - 1);
        if (count && visited[count - 1] == source)
            count--;
        if (count) {
            unsigned begin = reply_.size_;
            reply_.route_ = uint8_t(begin);
            reply_.first_hop_ = visited[0];
            reply_.bytes_[begin] = option[0];
            reply_.bytes_[begin + 1] = uint8_t(3 + count * 4);
            reply_.bytes_[begin + 2] = 4;
            for (unsigned at = 0; at < count; at++)
                put32(reply_.bytes_ + begin + 3 + at * 4, visited[at]);
            reply_.size_ += uint8_t(3 + count * 4);
        }
    }
    if (label != 255)
        append(label);
    reply_.size_ = uint8_t((reply_.size_ + 3) & ~3u);
    return 0;
}
} // namespace ax::ip4
