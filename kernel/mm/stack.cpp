// SPDX-License-Identifier: GPL-3.0-or-later
#include "mm/stack.hpp"
#include "mm/limits.hpp"
#include "process/task.hpp"

namespace ax {
namespace {
constexpr uint64_t guard_gap = 256 * page_size;
constexpr uint64_t mapping_flags = 7 | page_software | (1ull << 63);

uint64_t neighbour(uint64_t table, unsigned level, uint64_t base, uint64_t start, uint64_t end,
                   bool reverse) {
    const auto entries = static_cast<const uint64_t*>(physical(table));
    unsigned count = level == 4 ? 256 : 512;
    uint64_t span = 1ull << (12 + (level - 1) * 9);
    for (unsigned n = 0; n < count; n++) {
        unsigned i = reverse ? count - n - 1 : n;
        uint64_t address = base + i * span;
        if (!(entries[i] & page_mask) || address >= end || address + span <= start)
            continue;
        if (level == 1 || (entries[i] & 128))
            return reverse ? min(end, address + span) - page_size : max(start, address);
        uint64_t result =
            neighbour(entries[i] & page_mask, level - 1, address, start, end, reverse);
        if (result != user_limit)
            return result;
    }
    return user_limit;
}

bool accessible(uint64_t flags, bool write, bool execute) {
    return (flags & 5) == 5 && (!write || (flags & 2)) && (!execute || !(flags & (1ull << 63)));
}

bool grow_page(AddressSpace& space, uint64_t address, bool write, bool execute) {
    uint64_t bottom = neighbour(space.root, 4, 0, address, user_limit, false);
    if (bottom == user_limit || bottom == address)
        return false;
    uint64_t flags = *space.entry(bottom);
    if (!(flags & page_stack) || !accessible(flags, write, execute))
        return false;
    uint64_t top = bottom + page_size;
    while (top < user_limit) {
        auto entry = space.entry(top);
        if (!entry || !(*entry & page_mask) || (*entry & mapping_flags) != (flags & mapping_flags))
            break;
        top += page_size;
    }
    if (top - address > current->process->limits.soft(Resource::stack) ||
        !memory_growth_allowed(*current, address, bottom - address))
        return false;
    uint64_t previous = neighbour(space.root, 4, 0, 0, address, true);
    if (previous != user_limit) {
        uint64_t preceding = *space.entry(previous);
        if (!(preceding & page_stack) && (preceding & 1) &&
            address - previous - page_size < guard_gap)
            return false;
    }
    int protection = 1 | ((flags & 2) ? 2 : 0) | ((flags & (1ull << 63)) ? 0 : 4);
    uint64_t done = address;
    for (; done < bottom; done += page_size) {
        if (!space.map(done, page_size, protection)) {
            space.unmap(address, done - address);
            return false;
        }
        *space.entry(done) |= flags & page_software;
    }
    return true;
}
} // namespace

int memory_protection_range(const AddressSpace& memory, uint64_t& address, uint64_t& length,
                            uint64_t& protection) {
    constexpr uint64_t down = 0x1000000, up = 0x2000000;
    uint64_t grows = protection & (down | up);
    if (grows == (down | up) || address % page_size)
        return -22;
    if (!length)
        return 0;
    if (length > UINT64_MAX - (page_size - 1))
        return -12;
    length = align_up(length);
    if (address > UINT64_MAX - length)
        return -12;
    if (protection & ~(15ull | down | up))
        return -22;
    protection &= 15;
    if (address >= user_limit || length > user_limit - address)
        return -12;
    if (!grows)
        return 0;
    if (!memory.root)
        return -12;
    uint64_t end = address + length;
    uint64_t first = neighbour(memory.root, 4, 0, address, end, false);
    if (first == user_limit)
        return -12;
    auto& space = const_cast<AddressSpace&>(memory);
    uint64_t flags = *space.entry(first);
    if (grows == up)
        return first > address ? -12 : -22;
    if (!(flags & page_stack))
        return -22;
    uint64_t bottom = first;
    while (bottom >= page_size) {
        auto previous = space.entry(bottom - page_size);
        if (!previous || !(*previous & page_mask) ||
            (*previous & mapping_flags) != (flags & mapping_flags))
            break;
        bottom -= page_size;
    }
    address = bottom;
    length = end - bottom;
    return 0;
}

bool grow_user_stack(const AddressSpace& memory, uint64_t address, size_t length, bool write,
                     bool execute) {
    if (!current || !current->memory || &current->memory->space != &memory ||
        address >= user_limit || length > user_limit - address || !memory.root)
        return false;
    auto& space = const_cast<AddressSpace&>(memory);
    for (uint64_t page = align_down(address); page < address + length; page += page_size) {
        auto entry = space.entry(page);
        if (entry && (*entry & page_mask)) {
            if (!accessible(*entry, write, execute))
                return false;
        } else if (!grow_page(space, page, write, execute))
            return false;
    }
    return true;
}
} // namespace ax
