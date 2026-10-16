// SPDX-License-Identifier: GPL-3.0-or-later
#include "mm/limits.hpp"
#include "process/task.hpp"

namespace ax {
namespace {
uint64_t data_limit(const Task& task) {
    uint64_t limit = task.process->limits.soft(Resource::data);
    // Linux permits the hard data allowance for mappings when the soft value is zero.
    return limit ? limit : task.process->limits.hard(Resource::data);
}

bool fits(uint64_t used, uint64_t growth, uint64_t limit) {
    return growth <= limit && used <= limit - growth;
}
} // namespace

bool memory_growth_allowed(const Task& task, uint64_t start, size_t length, bool replace) {
    uint64_t limit = task.process->limits.soft(Resource::address_space);
    if (limit == resource_infinity)
        return true;
    uint64_t used = task.memory->space.mapped_size();
    if (replace)
        used -= task.memory->space.mapped_size(start, length);
    return fits(used, length, limit);
}

bool data_growth_allowed(const Task& task, uint64_t start, size_t length, bool replace) {
    uint64_t limit = data_limit(task);
    if (limit == resource_infinity)
        return true;
    uint64_t growth = length;
    if (replace)
        growth -= task.memory->space.mapped_size(start, length);
    return fits(task.memory->space.private_writable_size(), growth, limit);
}

bool memory_protection_allowed(const Task& task, uint64_t start, size_t length, int protection) {
    if (!(protection & 2) || data_limit(task) == resource_infinity)
        return true;
    auto& space = task.memory->space;
    uint64_t extra = space.private_writable_size(start, length, true) -
                     space.private_writable_size(start, length);
    if (!extra)
        return true;
    // Linux checks a write upgrade only when the old protection passes its growth test.
    if (!fits(space.mapped_size(), length, task.process->limits.soft(Resource::address_space)))
        return true;
    return fits(space.private_writable_size(), extra, data_limit(task));
}

bool heap_change_allowed(const Task& task, uint64_t address) {
    uint64_t limit = task.process->limits.soft(Resource::data);
    return address >= task.memory->brk_base &&
           (limit == resource_infinity ||
            fits(task.memory->initial_data_size, address - task.memory->brk_base, limit));
}
} // namespace ax
