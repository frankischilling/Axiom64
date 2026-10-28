// SPDX-License-Identifier: GPL-3.0-or-later
#include "net/ipv4/multicast.hpp"

namespace ax::ip4 {
namespace {
MulticastMembership::Entry* slot(MulticastMembership& owner, unsigned index, uint32_t group,
                                 bool allow_vacant) {
    MulticastMembership::Entry* vacant = nullptr;
    for (auto& entry : owner.entries) {
        if (entry.index == index && entry.group == group)
            return &entry;
        if (!entry.index && !vacant)
            vacant = &entry;
    }
    return allow_vacant ? vacant : nullptr;
}

int valid(unsigned index, uint32_t group) {
    if (!multicast(group))
        return -22;
    return index && index < MulticastHost::interface_capacity ? 0 : -19;
}

bool same_interest(const MulticastSourceAggregate& first, const MulticastSourceAggregate& second) {
    if (bool(first.owners()) != bool(second.owners()) || first.mode() != second.mode())
        return false;
    uint32_t before[64], after[64];
    unsigned count = first.sources(before, 64);
    if (count != second.sources(after, 64))
        return false;
    for (unsigned n = 0; n < count; n++)
        if (before[n] != after[n])
            return false;
    return true;
}
} // namespace

int MulticastHost::commit(MulticastMembership::Entry& owner, unsigned index, uint32_t group,
                          const MulticastSourceFilter& filter, uint64_t now) {
    synchronize(index, now);
    auto entry = find(index, group);
    if (!entry)
        for (auto& candidate : groups)
            if (!candidate.index) {
                entry = &candidate;
                break;
            }
    if (!entry)
        return -105;
    auto candidate = entry->interest;
    if (int error = candidate.update(owner.filter.view(), filter.view()))
        return error;
    bool difference = !same_interest(entry->interest, candidate);
    bool previously_present = entry->interest.owners() != 0;
    // Report history reserves hidden contributors before ownership changes.
    // Final close can then expose any remaining owner without allocation.
    if (int error = entry->reports.change(candidate, links[index].robustness))
        return error;
    entry->index = index;
    entry->address = group;
    entry->interest = candidate;
    owner = filter.present() ? MulticastMembership::Entry{group, index, filter}
                             : MulticastMembership::Entry{};
    if (difference)
        changed(*entry, previously_present, now);
    return 0;
}

int MulticastHost::join(MulticastMembership& owner, unsigned index, uint32_t group, uint64_t now) {
    if (int error = valid(index, group))
        return error;
    auto entry = slot(owner, index, group, true);
    if (!entry)
        return -105;
    auto candidate = entry->filter;
    if (int error = candidate.join())
        return error;
    return commit(*entry, index, group, candidate, now);
}

int MulticastHost::leave(MulticastMembership& owner, unsigned index, uint32_t group, uint64_t now) {
    if (!multicast(group))
        return -22;
    for (auto& entry : owner.entries) {
        if (entry.group != group || (index && entry.index != index))
            continue;
        MulticastSourceFilter absent;
        return commit(entry, entry.index, group, absent, now);
    }
    return -99;
}

int MulticastHost::source(MulticastMembership& owner, unsigned index, uint32_t group, unsigned mode,
                          bool add, uint32_t address, unsigned limit, uint64_t now) {
    if (int error = valid(index, group))
        return error;
    auto entry = slot(owner, index, group, add && mode == 1);
    if (!entry)
        return add && mode == 1 ? -105 : -22;
    auto candidate = entry->filter;
    int result = candidate.source(mode, add, address, limit);
    if (!entry->index && !candidate.present())
        return result;
    // Native removal may return an error after changing an unallocated empty
    // list's mode. Commit that observable state only if aggregate admission
    // also succeeds. A capacity failure leaves both owners unchanged.
    if (int error = commit(*entry, index, group, candidate, now))
        return error;
    return result;
}

int MulticastHost::replace(MulticastMembership& owner, unsigned index, uint32_t group,
                           unsigned mode, const uint32_t* addresses, unsigned count, unsigned limit,
                           uint64_t now) {
    if (int error = valid(index, group))
        return error;
    auto entry = slot(owner, index, group, false);
    MulticastSourceFilter candidate = entry ? entry->filter : MulticastSourceFilter{};
    int result = candidate.replace(mode, addresses, count, limit);
    if (result || !entry)
        return result;
    return commit(*entry, index, group, candidate, now);
}

const MulticastSourceFilter* MulticastHost::filter(const MulticastMembership& owner, unsigned index,
                                                   uint32_t group) const {
    for (const auto& entry : owner.entries)
        if (entry.index == index && entry.group == group)
            return &entry.filter;
    return nullptr;
}

void MulticastHost::close(MulticastMembership& owner, uint64_t now) {
    for (auto& entry : owner.entries)
        if (entry.index)
            leave(owner, entry.index, entry.group, now);
}

bool MulticastHost::member(unsigned index, uint32_t group) const {
    if (!index || index >= interface_capacity || !links[index].up)
        return false;
    if (group == 0xe0000001)
        return true;
    for (const auto& entry : groups)
        if (entry.index == index && entry.address == group && entry.interest.owners())
            return true;
    return false;
}

bool MulticastHost::accepts_source(unsigned index, uint32_t group, uint32_t source) const {
    if (!member(index, group))
        return false;
    if (!source || group == 0xe0000001)
        return true;
    for (const auto& entry : groups)
        if (entry.index == index && entry.address == group)
            return entry.interest.accepts(source);
    return false;
}

bool MulticastHost::accepts(const MulticastMembership& owner, unsigned index, uint32_t group,
                            uint32_t source) const {
    if (!accepts_source(index, group, source))
        return false;
    if (auto entry = filter(owner, index, group))
        return entry->accepts(source);
    return owner.all;
}
} // namespace ax::ip4
