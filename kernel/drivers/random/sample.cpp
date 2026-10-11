// SPDX-License-Identifier: GPL-3.0-or-later
#include "drivers/random/sample.hpp"

namespace ax {
bool EntropyRequest::begin(uint64_t cookie, uint16_t head, uint64_t now) {
    if (pending_ || !cookie || !remaining() || expired(now))
        return false;
    if (!filled_)
        deadline_ = now > UINT64_MAX - 200 ? UINT64_MAX : now + 200;
    cookie_ = cookie;
    head_ = head;
    pending_ = true;
    return true;
}

int EntropyRequest::complete(uint64_t cookie, uint16_t head, const void* data, unsigned length) {
    if (!pending_ || cookie != cookie_ || head != head_ || !length || length > remaining())
        return -5;
    const auto bytes = static_cast<const uint8_t*>(data);
    for (unsigned i = 0; i < length; i++)
        bytes_[filled_++] = bytes[i];
    pending_ = false;
    return remaining() ? 0 : 1;
}

void EntropyRequest::reset() {
    random::erase(bytes_, sizeof(bytes_));
    cookie_ = deadline_ = 0;
    head_ = 0;
    filled_ = consumed_ = 0;
    pending_ = false;
}

bool EntropyRequest::word(void* context, uint64_t& value) {
    auto& sample = *static_cast<EntropyRequest*>(context);
    if (sample.pending_ || sample.remaining() || sample.consumed_ == 4)
        return false;
    value = 0;
    for (unsigned i = 0; i < 8; i++)
        value |= uint64_t(sample.bytes_[sample.consumed_ * 8 + i]) << (8 * i);
    sample.consumed_++;
    return true;
}
} // namespace ax
