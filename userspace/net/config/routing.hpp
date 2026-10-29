// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include <stddef.h>
#include <stdint.h>

namespace ax::net {
namespace detail {
struct RouteSnapshot;
}

struct Address {
    uint32_t address = 0, mask = 0, broadcast = 0;
    unsigned index = 0;
};

struct Route {
    uint32_t destination = 0, mask = 0, gateway = 0, metric = 0;
    unsigned index = 0;
    uint8_t protocol = 16, scope = 253;
    uint32_t preferred_source = 0;
    uint8_t tos = 0;
};

// A private kernel-port socket with bounded requests and owned reply snapshots.
// Changes require explicit interface, nonzero priority, protocol and scope to
// avoid wildcard removal. Positive errno results; failed lists leave output intact.
class Routing {
  public:
    static constexpr size_t capacity = 65;

    Routing() = default;

    ~Routing();

    Routing(const Routing&) = delete;

    Routing& operator=(const Routing&) = delete;

    int open();

    int change(const Route&, bool remove);

    int change(const Address&, bool remove);

    int list(Route*, size_t capacity, size_t& count, unsigned index = 0, uint8_t protocol = 0);

  private:
    friend class Configuration;
    int fd_ = -1;
    uint32_t port_ = 0, sequence_ = 0;

    int close();

    int send(void*, size_t, uint32_t&);

    int receive(void*, size_t, size_t&, uint64_t deadline);

    int acknowledge(void*, size_t);

    int inventory(Route*, size_t, size_t&, unsigned, uint8_t, detail::RouteSnapshot*);

    int preserve(detail::RouteSnapshot&, unsigned, const Route*, unsigned, const Route*, unsigned);

    int restore(const detail::RouteSnapshot&, unsigned);

    static bool valid(const detail::RouteSnapshot&, unsigned);
};
} // namespace ax::net
