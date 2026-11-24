// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/fs/tmpfs.cpp
 * @brief   Parse and apply bounded tmpfs mount options.
 * @author  frankischilling
 * @date    2026-11-23
 *
 * Copyright (C) 2026 frankischilling
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://gnu.org/licenses/>.
 */
#include "fs/tmpfs.hpp"
#include "fs/vfs.hpp"

namespace ax {
namespace {
struct Options {
    TmpfsLimits limits;
    uint32_t mode = 01777, uid = 0, gid = 0;
};

bool key_is(const char* key, size_t length, const char* name) {
    return length == strlen(name) && !memcmp(key, name, length);
}

bool number(const char*& at, const char* end, unsigned base, uint64_t& value) {
    value = 0;
    const char* first = at;
    while (at != end && *at >= '0' && unsigned(*at - '0') < base) {
        const unsigned digit = unsigned(*at++ - '0');
        if (value > (UINT64_MAX - digit) / base)
            return false;
        value = value * base + digit;
    }
    return at != first;
}

bool scaled(uint64_t& value, char suffix) {
    unsigned shift;
    switch (suffix) {
    case 'K':
    case 'k':
        shift = 10;
        break;
    case 'M':
    case 'm':
        shift = 20;
        break;
    case 'G':
    case 'g':
        shift = 30;
        break;
    case 'T':
    case 't':
        shift = 40;
        break;
    default:
        return false;
    }
    if (value > (UINT64_MAX >> shift))
        return false;
    value <<= shift;
    return true;
}

bool read_option(Options& settings, const char* key, const char* value, const char* end,
                 uint64_t ram_pages) {
    const size_t key_length = value - key - 1;
    uint64_t parsed;
    if (key_is(key, key_length, "size")) {
        if (!number(value, end, 10, parsed))
            return false;
        if (end - value == 1 && *value == '%') {
            if (parsed > 100)
                return false;
            settings.limits.pages = ram_pages * parsed / 100;
            return true;
        }
        if (value != end && (end - value != 1 || !scaled(parsed, *value)))
            return false;
        settings.limits.pages = parsed / page_size + bool(parsed % page_size);
        return true;
    }
    if (key_is(key, key_length, "nr_inodes") || key_is(key, key_length, "nr_blocks")) {
        if (!number(value, end, 10, parsed) ||
            (value != end && (end - value != 1 || !scaled(parsed, *value))))
            return false;
        if (key_is(key, key_length, "nr_inodes"))
            settings.limits.inodes = parsed;
        else
            settings.limits.pages = parsed;
        return true;
    }
    if (key_is(key, key_length, "mode")) {
        if (!number(value, end, 8, parsed) || value != end || parsed > 07777)
            return false;
        settings.mode = parsed;
        return true;
    }
    if (!number(value, end, 10, parsed) || value != end || parsed >= UINT32_MAX)
        return false;
    if (key_is(key, key_length, "uid"))
        settings.uid = parsed;
    else if (key_is(key, key_length, "gid"))
        settings.gid = parsed;
    else
        return false;
    return true;
}
} // namespace

TmpfsLimits* tmpfs_limits(const Mount* mount) {
    return mount->ops == &tmpfs_ops ? static_cast<TmpfsLimits*>(mount->data) : nullptr;
}

int tmpfs_mount(Mount* mount, const char* options) {
    const uint64_t ram_pages = physical_memory_stats().total / page_size;
    Options settings{{ram_pages / 2, ram_pages / 2}};
    for (const char* option = options; option && *option;) {
        const char* end = option;
        const char* equals = nullptr;
        for (; *end && *end != ','; ++end)
            if (*end == '=' && !equals)
                equals = end;
        if (end != option &&
            (!equals || !read_option(settings, option, equals + 1, end, ram_pages)))
            return -22;
        option = *end ? end + 1 : end;
    }
    auto limits = static_cast<TmpfsLimits*>(alloc(sizeof(TmpfsLimits)));
    if (!limits)
        return -12;
    *limits = settings.limits;
    mount->data = limits;
    mount->root = ramfs_root(mount, settings.mode);
    if (!mount->root) {
        release(limits);
        mount->data = nullptr;
        return -28;
    }
    mount->root->uid = settings.uid;
    mount->root->gid = settings.gid;
    return 0;
}
} // namespace ax
