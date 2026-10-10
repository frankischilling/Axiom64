// SPDX-License-Identifier: GPL-3.0-or-later
#include "net/inet.hpp"
#include "net/ipv4.hpp"
#include "process/task.hpp"

namespace ax {
namespace {
struct Ifreq {
    char name[16];
    uint8_t value[24];
};

static_assert(sizeof(Ifreq) == 40);

struct RouteRequest {
    uint64_t padding1;
    InetAddress destination, gateway, mask;
    uint16_t flags, padding2;
    uint32_t padding3;
    uint64_t padding4;
    uint8_t tos, route_class;
    uint16_t padding5[3];
    int16_t metric;
    uint8_t padding6[6];
    uint64_t device, mtu, window;
    uint16_t irtt;
    uint8_t padding7[6];
};

static_assert(sizeof(RouteRequest) == 120);
static_assert(offsetof(RouteRequest, destination) == 8);
static_assert(offsetof(RouteRequest, flags) == 56);
static_assert(offsetof(RouteRequest, metric) == 80);
static_assert(offsetof(RouteRequest, device) == 88);

static const NetInfo* interface(unsigned index) {
    if (index != ipv4_loopback)
        return net_info(index);
    static NetInfo lo;
    lo.index = ipv4_loopback;
    memcpy(lo.name, "lo", 3);
    lo.mtu = lo.maximum_mtu = 65536;
    lo.administrative = lo.carrier = lo.live = lo.writable = true;
    return &lo;
}

static unsigned interface(const char* name) {
    if (!strcmp(name, "lo"))
        return ipv4_loopback;
    for (unsigned i = 1; auto info = net_info(i); i++)
        if (!strcmp(info->name, name))
            return i;
    return 0;
}

static void address(Ifreq& request, uint32_t value) {
    InetAddress result{2, 0, __builtin_bswap32(value), {}};
    memset(request.value, 0, sizeof(request.value));
    memcpy(request.value, &result, sizeof(result));
}

static int routes(Task& task, uint64_t request, uint64_t pointer) {
    RouteRequest entry;
    if (!task.memory->space.copy_in(&entry, pointer, sizeof(entry)))
        return -14;
    uint32_t mask = __builtin_bswap32(entry.mask.address);
    if (entry.destination.family != 2 ||
        (!(entry.flags & 4) && entry.mask.family != 2 && (mask || entry.mask.family)))
        return -97;
    if (entry.flags & ~uint16_t(7))
        return -95;
    if (entry.metric < 0)
        return -22;
    Ipv4Route route{__builtin_bswap32(entry.destination.address),
                    (entry.flags & 4) ? UINT32_MAX : mask, 0, 0,
                    entry.metric ? unsigned(entry.metric - 1) : 0};
    if (entry.flags & 2) {
        if (entry.gateway.family != 2)
            return -97;
        route.gateway = __builtin_bswap32(entry.gateway.address);
        if (!route.gateway)
            return -22;
    }
    if (entry.device) {
        char name[16];
        if (!task.memory->space.string(entry.device, name, sizeof(name)))
            return -14;
        route.index = interface(name);
        if (!route.index)
            return -19;
    }
    return ipv4_route(route, request == 0x890c);
}

static int list(Task& task, uint64_t pointer) {
    struct Ifconf {
        int32_t length, padding;
        uint64_t buffer;
    } config;

    static_assert(sizeof(Ifconf) == 16);
    if (!task.memory->space.copy_in(&config, pointer, sizeof(config)))
        return -14;
    if (config.length < 0)
        return -22;
    const size_t capacity = config.buffer ? size_t(config.length) : SIZE_MAX;
    size_t copied = 0;
    for (unsigned index = 1; index <= ipv4_loopback; index++) {
        const auto info = interface(index);
        const auto ip = ipv4_config(index);
        if (!info || !ip || !ip->address || sizeof(Ifreq) > capacity - copied)
            continue;
        Ifreq entry{};
        memcpy(entry.name, info->name, sizeof(entry.name));
        address(entry, ip->address);
        if (config.buffer &&
            !task.memory->space.copy_out(config.buffer + copied, &entry, sizeof(entry)))
            return -14;
        copied += sizeof(entry);
    }
    config.length = copied;
    return task.memory->space.copy_out(pointer, &config, sizeof(config)) ? 0 : -14;
}
} // namespace

int64_t net_ioctl(Task& task, uint64_t request, uint64_t pointer) {
    if ((request == 0x890b || request == 0x890c || request == 0x8914 || request == 0x8916 ||
         request == 0x891a || request == 0x891c || request == 0x8922) &&
        !capable(task.credentials, Capability::net_admin))
        return -1;
    net_poll();
    if (request == 0x890b || request == 0x890c)
        return routes(task, request, pointer);
    if (request == 0x8912)
        return list(task, pointer);
    Ifreq req;
    if (!task.memory->space.copy_in(&req, pointer, sizeof(req)))
        return -14;
    unsigned index = 0;
    if (request == 0x8910)
        memcpy(&index, req.value, 4);
    else {
        req.name[15] = 0;
        index = interface(req.name);
    }
    const auto info = interface(index);
    if (!info)
        return -19;
    switch (request) {
    case 0x8910:
        memcpy(req.name, info->name, 16);
        break;
    case 0x8933:
        memcpy(req.value, &info->index, 4);
        break;
    case 0x8913: {
        uint16_t flags = index == ipv4_loopback ? 0x49
                                                : 2 | 0x1000 | (info->administrative ? 1 : 0) |
                                                      (info->carrier && info->live ? 0x40 : 0);
        memcpy(req.value, &flags, 2);
        break;
    }
    case 0x8914: {
        uint16_t flags;
        memcpy(&flags, req.value, 2);
        if (index == ipv4_loopback)
            return (flags & 1) && !(flags & ~uint16_t(0x49)) ? 0 : -95;
        if (flags & ~uint16_t(1 | 2 | 0x40 | 0x1000))
            return -95;
        return net_configure(index, flags & 1, info->mtu);
    }
    case 0x8915:
    case 0x8919:
    case 0x891b: {
        const auto ip = ipv4_config(index);
        if (!ip || !ip->address)
            return -99;
        address(req, request == 0x8915   ? ip->address
                     : request == 0x8919 ? ip->broadcast
                                         : ip->mask);
        break;
    }
    case 0x8916:
    case 0x891a:
    case 0x891c: {
        InetAddress input;
        memcpy(&input, req.value, sizeof(input));
        if (input.family != 2)
            return -97;
        auto changed = *ipv4_config(index);
        uint32_t value = __builtin_bswap32(input.address);
        if (request == 0x8916)
            changed.address = value;
        else if (request == 0x891c)
            changed.mask = value;
        changed.broadcast = request == 0x891a ? value : 0;
        return ipv4_configure(index, changed);
    }
    case 0x8921:
        memcpy(req.value, &info->mtu, 4);
        break;
    case 0x8922: {
        uint32_t mtu;
        memcpy(&mtu, req.value, 4);
        return index == ipv4_loopback ? -95 : net_configure(index, info->administrative, mtu);
    }
    case 0x8927: {
        uint16_t family = index == ipv4_loopback ? 772 : 1;
        memset(req.value, 0, sizeof(req.value));
        memcpy(req.value, &family, 2);
        memcpy(req.value + 2, info->mac, 6);
        break;
    }
    default:
        return -95;
    }
    return task.memory->space.copy_out(pointer, &req, sizeof(req)) ? 0 : -14;
}
} // namespace ax
