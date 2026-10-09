// SPDX-License-Identifier: GPL-3.0-or-later
#include "net/config/configuration.hpp"
#include "net/dhcp/transport.hpp"
#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

namespace ax::net {
namespace {
constexpr size_t journal_header = 60, route_bytes = 24;
constexpr uint8_t magic[]{'A', 'X', 'N', 'W', 'O', 'W', 'N', '1'};

bool mask_valid(uint32_t mask) {
    uint32_t bits = ~mask;
    return !(bits & (bits + 1));
}

bool unicast(uint32_t address) {
    unsigned first = address >> 24;
    return first && first != 127 && first < 224;
}

bool host(uint32_t address, uint32_t mask) {
    uint32_t bits = ~mask;
    return unicast(address) && mask_valid(mask) &&
           (bits < 2 || ((address & bits) && (address & bits) != bits));
}

bool same_route(const Route& a, const Route& b) {
    return a.destination == b.destination && a.mask == b.mask && a.gateway == b.gateway &&
           a.metric == b.metric && a.index == b.index && a.protocol == b.protocol &&
           a.scope == b.scope;
}

uint32_t get(const uint8_t* bytes) {
    return uint32_t(bytes[0]) | (uint32_t(bytes[1]) << 8) | (uint32_t(bytes[2]) << 16) |
           (uint32_t(bytes[3]) << 24);
}

void put(uint8_t* bytes, uint32_t value) {
    for (unsigned i = 0; i < 4; i++)
        bytes[i] = value >> (i * 8);
}

uint32_t digest(const uint8_t* bytes, size_t count) {
    uint32_t result = 2166136261;
    for (size_t i = 0; i < count; i++)
        result = (result ^ bytes[i]) * 16777619;
    return result;
}

int address_ioctl(int fd, const char* name, unsigned code, uint32_t& value) {
    ifreq request{};
    memcpy(request.ifr_name, name, strlen(name) + 1);
    sockaddr_in endpoint{};
    endpoint.sin_family = AF_INET;
    endpoint.sin_addr.s_addr = htonl(value);
    memcpy(&request.ifr_addr, &endpoint, sizeof(endpoint));
    if (ioctl(fd, code, &request) < 0)
        return errno;
    memcpy(&endpoint, &request.ifr_addr, sizeof(endpoint));
    value = ntohl(endpoint.sin_addr.s_addr);
    return 0;
}
} // namespace

Configuration::~Configuration() {
    close();
}

int Configuration::close() {
    int error = control_ >= 0 && ::close(control_) < 0 ? errno : 0;
    control_ = -1;
    store_ = nullptr;
    int closed = routing_.close();
    if (!error)
        error = closed;
    active_ = before_ = after_ = {};
    pending_ = false;
    return error;
}

int Configuration::open(const dhcp::Interface& interface, const Store& runtime) {
    if (control_ >= 0 || store_)
        return EALREADY;
    const uint8_t zero[6]{};
    if (!interface.index || interface.index > 8 || !interface.name[0] ||
        strnlen(interface.name, sizeof(name_)) == sizeof(name_) ||
        (interface.identity.mac[0] & 1) || !memcmp(interface.identity.mac, zero, 6))
        return EINVAL;
    control_ = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (control_ < 0)
        return errno;
    ifreq request{};
    memcpy(request.ifr_name, interface.name, sizeof(name_));
    int error = 0;
    if (ioctl(control_, SIOCGIFINDEX, &request) < 0)
        error = errno;
    else if (unsigned(request.ifr_ifindex) != interface.index)
        error = ESTALE;
    else if (ioctl(control_, SIOCGIFHWADDR, &request) < 0)
        error = errno;
    else if (request.ifr_hwaddr.sa_family != 1 ||
             memcmp(request.ifr_hwaddr.sa_data, interface.identity.mac, 6))
        error = ESTALE;
    if (!error)
        error = routing_.open();
    if (error) {
        ::close(control_);
        control_ = -1;
        return error;
    }
    store_ = &runtime;
    index_ = interface.index;
    memcpy(name_, interface.name, sizeof(name_));
    memcpy(mac_, interface.identity.mac, sizeof(mac_));
    error = read_journal(before_, after_);
    if (error == ENOENT)
        return 0;
    if (error) {
        close();
        return error;
    }
    pending_ = true;
    return withdraw();
}

bool Configuration::valid(const Snapshot& value) const {
    if (value.count > dhcp::max_routes + 1)
        return false;
    if (!value.address)
        return !value.mask && !value.broadcast && !value.count;
    uint32_t broadcast = ~value.mask < 2 ? 0 : value.address | ~value.mask;
    if (!host(value.address, value.mask) || value.broadcast != broadcast)
        return false;
    for (unsigned i = 0; i < value.count; i++) {
        const auto& route = value.routes[i];
        if (!mask_valid(route.mask) || (route.destination & route.mask) != route.destination ||
            route.index != index_ || route.metric < 2 || route.metric > 32767 ||
            (route.protocol != 4 && route.protocol != 16) ||
            (route.gateway ? route.scope != 0 : route.scope != 253) ||
            (route.gateway && (!host(route.gateway, value.mask) || route.gateway == value.address ||
                               (route.gateway & value.mask) != (value.address & value.mask))))
            return false;
        for (unsigned j = 0; j < i; j++)
            if (route.destination == value.routes[j].destination &&
                route.mask == value.routes[j].mask)
                return false;
    }
    return true;
}

int Configuration::build(uint32_t address, const dhcp::Parameters& parameters, unsigned metric,
                         uint8_t protocol, Snapshot& output) const {
    if (!parameters.has_mask || parameters.route_count > dhcp::max_routes ||
        parameters.dns_count > dhcp::max_dns)
        return EINVAL;
    Snapshot desired;
    desired.address = address;
    desired.mask = parameters.mask;
    desired.broadcast = ~desired.mask < 2 ? 0 : address | ~desired.mask;
    if (!metric)
        metric = 100 + index_;
    if (metric < 2 || metric > 32767 || (protocol != 4 && protocol != 16))
        return EINVAL;
    auto add = [&](uint32_t destination, uint32_t mask, uint32_t gateway) {
        desired.routes[desired.count++] = {
            destination, mask, gateway, metric, index_, protocol, uint8_t(gateway ? 0 : 253)};
    };
    // An option-121 list overrides the Router option, including an empty list.
    if (!parameters.classless && parameters.router)
        add(0, 0, parameters.router);
    for (size_t i = 0; i < parameters.route_count; i++) {
        const auto& route = parameters.routes[i];
        add(route.destination, route.mask, route.gateway);
    }
    if (!valid(desired))
        return EINVAL;
    output = desired;
    return 0;
}

int Configuration::read_address(Snapshot& output) const {
    Snapshot found;
    int error = address_ioctl(control_, name_, SIOCGIFADDR, found.address);
    if (error == EADDRNOTAVAIL) {
        output = found;
        return 0;
    }
    if (!error)
        error = address_ioctl(control_, name_, SIOCGIFNETMASK, found.mask);
    if (!error)
        error = address_ioctl(control_, name_, SIOCGIFBRDADDR, found.broadcast);
    if (!error)
        output = found;
    return error;
}

int Configuration::set_address(const Snapshot& old, const Snapshot& desired) {
    Snapshot current;
    int error = read_address(current);
    if (error)
        return error;
    auto matches = [&](const Snapshot& value) {
        return current.address == value.address &&
               (!current.address ||
                (current.mask == value.mask && current.broadcast == value.broadcast));
    };
    if (matches(desired))
        return 0;
    if (current.address && !matches(old))
        return EBUSY;
    if (current.address) {
        Address remove{old.address, old.mask, old.broadcast, index_};
        error = mutate(remove, true);
        if (error)
            return error;
    }
    if (desired.address) {
        Address install{desired.address, desired.mask, desired.broadcast, index_};
        error = mutate(install, false);
        if (error == EEXIST && !read_address(current) && matches(desired))
            error = 0;
    }
    return error;
}

int Configuration::journal(const Snapshot& old, const Snapshot& desired) const {
    uint8_t bytes[journal_header + route_bytes * 2 * (dhcp::max_routes + 1)]{};
    size_t size = journal_header + route_bytes * (old.count + desired.count);
    memcpy(bytes, magic, sizeof(magic));
    put(bytes + 8, size);
    put(bytes + 16, index_);
    memcpy(bytes + 20, mac_, sizeof(mac_));
    const Snapshot* entries[]{&old, &desired};
    size_t at = journal_header;
    for (unsigned group = 0; group < 2; group++) {
        const auto& value = *entries[group];
        size_t offset = group ? 44 : 28;
        put(bytes + offset, value.address);
        put(bytes + offset + 4, value.mask);
        put(bytes + offset + 8, value.broadcast);
        put(bytes + offset + 12, value.count);
        for (unsigned i = 0; i < value.count; i++) {
            const auto& route = value.routes[i];
            put(bytes + at, route.destination);
            put(bytes + at + 4, route.mask);
            put(bytes + at + 8, route.gateway);
            put(bytes + at + 12, route.metric);
            put(bytes + at + 16, route.index);
            bytes[at + 20] = route.protocol;
            bytes[at + 21] = route.scope;
            at += route_bytes;
        }
    }
    put(bytes + 12, digest(bytes + 16, size - 16));
    return store_->write(name_, ".owned", bytes, size);
}

int Configuration::read_journal(Snapshot& old, Snapshot& desired) const {
    uint8_t bytes[4096];
    size_t size = 0;
    int error = store_->read(name_, ".owned", reinterpret_cast<char*>(bytes), sizeof(bytes), size);
    if (error)
        return error;
    if (size < journal_header || memcmp(bytes, magic, sizeof(magic)) || get(bytes + 8) != size ||
        get(bytes + 12) != digest(bytes + 16, size - 16) || bytes[26] || bytes[27])
        return EINVAL;
    if (get(bytes + 16) != index_ || memcmp(bytes + 20, mac_, sizeof(mac_)))
        return ESTALE;
    Snapshot saved[2];
    size_t at = journal_header;
    for (unsigned group = 0; group < 2; group++) {
        auto& value = saved[group];
        size_t offset = group ? 44 : 28;
        value.address = get(bytes + offset);
        value.mask = get(bytes + offset + 4);
        value.broadcast = get(bytes + offset + 8);
        value.count = get(bytes + offset + 12);
        if (value.count > dhcp::max_routes + 1 || value.count > (size - at) / route_bytes)
            return EINVAL;
        for (unsigned i = 0; i < value.count; i++) {
            auto& route = value.routes[i];
            route.destination = get(bytes + at);
            route.mask = get(bytes + at + 4);
            route.gateway = get(bytes + at + 8);
            route.metric = get(bytes + at + 12);
            route.index = get(bytes + at + 16);
            route.protocol = bytes[at + 20];
            route.scope = bytes[at + 21];
            if (bytes[at + 22] || bytes[at + 23])
                return EINVAL;
            at += route_bytes;
        }
        if (!valid(value))
            return EINVAL;
    }
    if (at != size)
        return EINVAL;
    old = saved[0];
    desired = saved[1];
    return 0;
}

int Configuration::preflight(const Snapshot& desired, bool& unchanged) {
    Snapshot current;
    int error = read_address(current);
    if (error)
        return error;
    auto same_address = [](const Snapshot& a, const Snapshot& b) {
        return a.address == b.address && a.mask == b.mask && a.broadcast == b.broadcast;
    };
    if (current.address && !same_address(current, active_))
        return EBUSY;
    Route saved[64];
    size_t count = 0;
    error = routing_.list(saved, 64, count);
    if (error)
        return error;
    unchanged = same_address(current, desired) && active_.count == desired.count;
    for (unsigned i = 0; i < desired.count; i++) {
        bool present = false;
        for (size_t j = 0; j < count; j++) {
            if (same_route(desired.routes[i], saved[j]))
                present = true;
        }
        bool retained = false;
        for (unsigned k = 0; k < active_.count; k++)
            retained |= same_route(desired.routes[i], active_.routes[k]);
        unchanged &= present && retained;
    }
    if (!unchanged)
        for (unsigned i = 0; i < desired.count; i++)
            for (size_t j = 0; j < count; j++) {
                bool owned = false;
                for (unsigned k = 0; k < active_.count; k++)
                    owned |= same_route(saved[j], active_.routes[k]);
                if (!owned && desired.routes[i].destination == saved[j].destination &&
                    desired.routes[i].mask == saved[j].mask &&
                    desired.routes[i].metric == saved[j].metric)
                    return EEXIST;
            }
    return 0;
}

int Configuration::mutate(const Route& route, bool remove) {
    int error = routing_.change(route, remove);
    if (error == EBADF) {
        error = routing_.open();
        if (!error)
            error = routing_.change(route, remove);
    }
    return error;
}

int Configuration::mutate(const Address& address, bool remove) {
    int error = routing_.change(address, remove);
    if (error == EBADF) {
        error = routing_.open();
        if (!error)
            error = routing_.change(address, remove);
    }
    return error;
}

int Configuration::remove_routes(const Snapshot& value) {
    int result = 0;
    for (unsigned i = value.count; i; i--) {
        int error = mutate(value.routes[i - 1], true);
        if (error && error != ESRCH && !result)
            result = error;
    }
    return result;
}

int Configuration::add_routes(const Snapshot& value) {
    for (unsigned pass = 0; pass < 2; pass++)
        for (unsigned i = 0; i < value.count; i++) {
            const auto& route = value.routes[i];
            if (bool(route.gateway) != bool(pass))
                continue;
            int error = mutate(route, false);
            if (error == EEXIST) {
                Route saved[64];
                size_t count = 0;
                error = routing_.list(saved, 64, count, index_, route.protocol);
                bool exists = false;
                for (size_t j = 0; !error && j < count; j++)
                    exists |= same_route(saved[j], route);
                if (!error && !exists)
                    error = EEXIST;
            }
            if (error)
                return error;
        }
    return 0;
}

int Configuration::clear(const Snapshot& old, const Snapshot& desired) {
    int error = remove_routes(desired);
    int result = remove_routes(old);
    if (!error)
        error = result;
    Snapshot current;
    result = read_address(current);
    auto matches = [&](const Snapshot& value) {
        return value.address && current.address == value.address && current.mask == value.mask &&
               current.broadcast == value.broadcast;
    };
    if (!result && (matches(old) || matches(desired)))
        result = set_address(current, Snapshot{});
    if (!error)
        error = result;
    return error;
}

int Configuration::rollback(const Snapshot& old, const Snapshot& desired) {
    int error = remove_routes(desired);
    Snapshot current;
    int result = read_address(current);
    if (!error)
        error = result;
    if (!result && current.address &&
        !(current.address == desired.address && current.mask == desired.mask &&
          current.broadcast == desired.broadcast) &&
        !(current.address == old.address && current.mask == old.mask &&
          current.broadcast == old.broadcast))
        return error ? error : EBUSY;
    if (!error)
        error = set_address(current, old);
    if (!error)
        error = add_routes(old);
    if (!error)
        error = old.address ? journal(Snapshot{}, old) : store_->remove(name_, ".owned");
    if (!error) {
        active_ = old;
        pending_ = false;
        before_ = after_ = {};
    }
    return error;
}

int Configuration::apply(uint32_t address, const dhcp::Parameters& parameters, unsigned metric,
                         uint8_t protocol) {
    if (control_ < 0 || !store_)
        return EBADF;
    if (pending_) {
        int error = withdraw();
        if (error)
            return error;
    }
    Snapshot desired;
    int error = build(address, parameters, metric, protocol, desired);
    bool unchanged = false;
    if (!error)
        error = preflight(desired, unchanged);
    if (error || unchanged)
        return error;
    before_ = active_;
    after_ = desired;
    pending_ = true;
    error = journal(before_, after_);
    if (!error)
        error = remove_routes(before_);
    if (!error)
        error = set_address(before_, desired);
    if (!error)
        error = add_routes(desired);
    if (!error)
        error = journal(Snapshot{}, desired);
    if (error) {
        int restored = rollback(before_, after_);
        return restored ? restored : error;
    }
    active_ = desired;
    before_ = after_ = {};
    pending_ = false;
    return 0;
}

int Configuration::withdraw() {
    if (control_ < 0 || !store_)
        return EBADF;
    Snapshot old = pending_ ? before_ : active_;
    Snapshot desired = pending_ ? after_ : Snapshot{};
    int error = clear(old, desired);
    if (!error)
        error = store_->remove(name_, ".owned");
    if (!error) {
        active_ = before_ = after_ = {};
        pending_ = false;
    }
    return error;
}
} // namespace ax::net
