// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    userspace/net/config/profile.hpp
 * @brief   Network profile interface.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Defines stored network profile values and declares parsing and validation
 * operations.
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
#pragma once
#include "net/dhcp/wire.hpp"

namespace ax::net {
enum class Method : uint8_t { dhcp, fixed, disabled };

struct Profile {
    Method method = Method::dhcp;
    uint32_t address = 0;
    unsigned metric = 0; // Zero selects the interface's automatic metric.
    dhcp::Parameters parameters;
    char hostname[64]{"axiom64"};
};

bool valid_profile(const Profile&);

bool parse_profile(const void*, size_t, Profile&);

size_t format_profile(const Profile&, void*, size_t);

// Errors are positive errno values. Reads leave output unchanged on failure.
// Writes sync the temporary file, rename it, and sync the containing directory.
class Store {
  public:
    explicit Store(const char* directory);

    int read_profile(const char* interface, Profile&) const;

    int write_profile(const char* interface, const Profile&) const;

    int read_hint(const char* interface, const dhcp::Identity&, uint32_t&) const;

    int write_hint(const char* interface, const dhcp::Identity&, uint32_t address) const;

    int forget_hint(const char* interface) const;

  private:
    friend class Configuration;
    friend class Resolver;
    char directory_[256]{};

    int path(const char* interface, const char* suffix, char*, size_t) const;

    int read(const char* interface, const char* suffix, char*, size_t, size_t&,
             bool saved = false) const;

    int write(const char* interface, const char* suffix, const void*, size_t, unsigned mode = 0600,
              unsigned directory_mode = 0700, bool saved = false) const;

    int remove(const char* interface, const char* suffix, bool saved = false) const;
};
} // namespace ax::net
