// SPDX-License-Identifier: GPL-3.0-or-later
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
