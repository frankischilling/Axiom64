// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    userspace/net/config/resolver.hpp
 * @brief   Resolver configuration interface.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Declares the operations that render and update resolver settings from network
 * state.
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
#include "net/config/profile.hpp"

namespace ax::net {
// Owns generated resolver text, never a manual target or an unrecorded file.
// Store must outlive this object and use a volatile filesystem. Positive errno.
// Use a dedicated directory with traversable parents: new directories are 0755,
// resolver text is 0644, and the ownership record is 0600. Existing private
// or foreign-owned/writable directories are rejected rather than changing
// their access policy.
// Opening clears recorded stale metadata; close leaves ownership for recovery.
class Resolver {
  public:
    Resolver() = default;

    ~Resolver();

    Resolver(const Resolver&) = delete;

    Resolver& operator=(const Resolver&) = delete;

    int open(const Store& runtime, const char* target = "/etc/resolv.conf");

    void close();

    // Only DNS/domain/search fields are used. Zero metric selects 100 + index.
    int update(unsigned index, const dhcp::Parameters&, unsigned metric = 0);

    int withdraw(unsigned index);

    // Status of the last operation. Limited means complete lower-priority
    // nameservers/search names exceeded the documented output bounds.
    bool managed() const;

    bool limited() const;

  private:
    static constexpr size_t output_capacity = 1024;

    struct Row {
        bool used = false;
        unsigned metric = 0;
        size_t dns_count = 0;
        uint32_t dns[dhcp::max_dns]{};
        char search[512]{};
    };

    const Store* store_ = nullptr;
    char target_[300]{}, expected_[output_capacity]{};
    char before_[output_capacity]{}, after_[output_capacity]{};
    size_t expected_size_ = 0, before_size_ = 0, after_size_ = 0;
    Row rows_[8]{};
    bool managed_ = false, limited_ = false, pending_ = false;

    int target_policy(bool& manual) const;

    int ensure_link();

    int read_output(char*, size_t&) const;

    int read_record(char*, size_t&, char*, size_t&) const;

    int record(const char*, size_t, const char*, size_t) const;

    int restore();

    int publish(const char*, size_t);

    int commit(const Row*);

    static int render(const Row*, char*, size_t&, bool& limited);
};
} // namespace ax::net
