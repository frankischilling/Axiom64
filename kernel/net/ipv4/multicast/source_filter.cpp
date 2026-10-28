// SPDX-License-Identifier: GPL-3.0-or-later
#include "net/ipv4/source_filter.hpp"

namespace ax::ip4 {
int MulticastSourceFilter::join() {
    if (active)
        return -98;
    *this = {};
    active = true;
    return 0;
}

int MulticastSourceFilter::leave() {
    if (!active)
        return -99;
    *this = {};
    return 0;
}

int MulticastSourceFilter::source(unsigned mode, bool add, uint32_t address, unsigned limit) {
    if (mode > 1)
        return -22;
    if (!active) {
        if (!add || !mode)
            return -22;
        active = true;
    }
    if (list_allocated && filter_mode != mode)
        return -22;
    filter_mode = mode;
    if (add) {
        // Linux checks the configured limit before detecting a duplicate.
        if (count == capacity || (list_allocated && count >= limit))
            return -105;
        for (unsigned n = 0; n < count; n++)
            if (addresses[n] == address)
                return -99;
        addresses[count++] = address;
        list_allocated = true;
        return 0;
    }
    unsigned at = 0;
    while (at < count && addresses[at] != address)
        at++;
    if (at == count)
        return -99;
    if (mode && count == 1)
        return leave();
    for (unsigned n = at + 1; n < count; n++)
        addresses[n - 1] = addresses[n];
    addresses[--count] = 0;
    return 0;
}

int MulticastSourceFilter::replace(unsigned mode, const uint32_t* sources, unsigned size,
                                   unsigned limit) {
    if (mode > 1 || (size && !sources))
        return -22;
    if (size > capacity || size > limit)
        return -105;
    if (mode && !size)
        return leave();
    if (!active)
        return -22;
    MulticastSourceFilter candidate;
    candidate.active = true;
    candidate.filter_mode = mode;
    candidate.list_allocated = size != 0;
    candidate.count = size;
    for (unsigned n = 0; n < size; n++)
        candidate.addresses[n] = sources[n];
    *this = candidate;
    return 0;
}

unsigned MulticastSourceFilter::sources(uint32_t* output, unsigned available) const {
    for (unsigned n = 0; n < count && n < available; n++)
        output[n] = addresses[n];
    return count;
}

bool MulticastSourceFilter::accepts(uint32_t source) const {
    if (!active)
        return false;
    bool found = false;
    for (unsigned n = 0; n < count; n++)
        found |= addresses[n] == source;
    return filter_mode ? found : !found;
}
} // namespace ax::ip4
