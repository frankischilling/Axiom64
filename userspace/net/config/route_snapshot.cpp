// SPDX-License-Identifier: GPL-3.0-or-later
#include "net/config/route_snapshot.hpp"
#include <arpa/inet.h>
#include <errno.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <string.h>

namespace ax::net {
namespace {
bool same(const Route& a, const Route& b) {
    return a.destination == b.destination && a.mask == b.mask && a.gateway == b.gateway &&
           a.metric == b.metric && a.index == b.index && a.protocol == b.protocol &&
           a.scope == b.scope && a.preferred_source == b.preferred_source && a.tos == b.tos;
}

bool key(const Route& a, const Route& b) {
    return a.destination == b.destination && a.mask == b.mask && a.metric == b.metric &&
           a.tos == b.tos;
}

size_t record_size(const uint8_t* bytes) {
    nlmsghdr header;
    memcpy(&header, bytes, sizeof(header));
    return NLMSG_ALIGN(header.nlmsg_len);
}

bool owned(const Route& value, const Route* first, unsigned count) {
    for (unsigned n = 0; n < count; n++)
        if (same(value, first[n]))
            return true;
    return false;
}
} // namespace

int detail::decode_route(const void* data, size_t length, Route& value,
                         uint32_t* preferred_source) {
    const auto* bytes = static_cast<const uint8_t*>(data);
    nlmsghdr header;
    rtmsg body;
    if (length < 28)
        return EPROTO;
    memcpy(&header, bytes, sizeof(header));
    memcpy(&body, bytes + 16, sizeof(body));
    if (header.nlmsg_len != length || header.nlmsg_type != RTM_NEWROUTE ||
        body.rtm_family != AF_INET || body.rtm_dst_len > 32 || body.rtm_src_len ||
        body.rtm_type != RTN_UNICAST || body.rtm_table != RT_TABLE_MAIN)
        return EPROTO;
    Route found;
    found.mask = body.rtm_dst_len ? UINT32_MAX << (32 - body.rtm_dst_len) : 0;
    found.protocol = body.rtm_protocol;
    found.tos = body.rtm_tos;
    found.scope = body.rtm_scope;
    uint32_t source = 0, seen = 0;
    for (size_t at = 28; at < length;) {
        rtattr field;
        if (length - at < sizeof(field))
            return EPROTO;
        memcpy(&field, bytes + at, sizeof(field));
        if (field.rta_len < 4 || field.rta_len > length - at ||
            RTA_ALIGN(field.rta_len) > length - at)
            return EPROTO;
        if (field.rta_type == RTA_DST || field.rta_type == RTA_GATEWAY ||
            field.rta_type == RTA_PRIORITY || field.rta_type == RTA_OIF ||
            field.rta_type == RTA_PREFSRC || field.rta_type == RTA_TABLE) {
            if (field.rta_len != 8 || (seen & (1u << field.rta_type)))
                return EPROTO;
            seen |= 1u << field.rta_type;
            uint32_t number;
            memcpy(&number, bytes + at + 4, 4);
            switch (field.rta_type) {
            case RTA_DST:
                found.destination = ntohl(number);
                break;
            case RTA_GATEWAY:
                found.gateway = ntohl(number);
                break;
            case RTA_PRIORITY:
                found.metric = number;
                break;
            case RTA_OIF:
                found.index = number;
                break;
            case RTA_PREFSRC:
                source = ntohl(number);
                break;
            case RTA_TABLE:
                if (number != RT_TABLE_MAIN)
                    return EPROTO;
                break;
            }
        }
        at += RTA_ALIGN(field.rta_len);
    }
    if ((found.destination & found.mask) != found.destination)
        return EPROTO;
    found.preferred_source = source;
    value = found;
    if (preferred_source)
        *preferred_source = source;
    return 0;
}

bool Routing::valid(const detail::RouteSnapshot& snapshot, unsigned index) {
    if (snapshot.size > sizeof(snapshot.bytes))
        return false;
    for (size_t at = 0; at < snapshot.size;) {
        if (snapshot.size - at < sizeof(nlmsghdr))
            return false;
        nlmsghdr header;
        memcpy(&header, snapshot.bytes + at, sizeof(header));
        size_t bytes = NLMSG_ALIGN(header.nlmsg_len);
        Route value;
        if (header.nlmsg_len < 28 || bytes > snapshot.size - at ||
            detail::decode_route(snapshot.bytes + at, header.nlmsg_len, value) ||
            value.index != index)
            return false;
        at += bytes;
    }
    return true;
}

int Routing::preserve(detail::RouteSnapshot& snapshot, unsigned index, const Route* first,
                      unsigned first_count, const Route* second, unsigned second_count) {
    if (!valid(snapshot, index))
        return EINVAL;
    Route current[Routing::capacity];
    size_t count = 0;
    detail::RouteSnapshot packets;
    int error = inventory(current, Routing::capacity, count, index, 0, &packets);
    if (error)
        return error;
    auto result = snapshot;
    Route groups[Routing::capacity];
    size_t entry = 0, group_count = 0;
    for (size_t at = 0; at < packets.size; entry++) {
        size_t bytes = record_size(packets.bytes + at);
        const auto& value = current[entry];
        uint32_t preferred = 0;
        Route checked;
        if (detail::decode_route(packets.bytes + at, bytes, checked, &preferred))
            return EPROTO;
        bool automatic = value.protocol == RTPROT_KERNEL && value.scope == RT_SCOPE_LINK &&
                         !value.gateway && !value.metric && !value.tos && preferred &&
                         value.destination == (preferred & value.mask);
        if (!automatic && !owned(value, first, first_count) &&
            !owned(value, second, second_count)) {
            bool first_group = true;
            for (size_t n = 0; n < group_count; n++)
                first_group &= !key(value, groups[n]);
            if (first_group)
                groups[group_count++] = value;
            // Replace an old group once, retaining every current alias in it.
            detail::RouteSnapshot next;
            for (size_t old = 0; old < result.size;) {
                size_t size = record_size(result.bytes + old);
                Route earlier;
                if (detail::decode_route(result.bytes + old, size, earlier))
                    return EPROTO;
                if (!first_group || !key(value, earlier)) {
                    memcpy(next.bytes + next.size, result.bytes + old, size);
                    next.size += size;
                }
                old += size;
            }
            if (bytes > sizeof(next.bytes) - next.size)
                return ENOSPC;
            memcpy(next.bytes + next.size, packets.bytes + at, bytes);
            next.size += bytes;
            result = next;
        }
        at += bytes;
    }
    snapshot = result;
    return 0;
}

int Routing::restore(const detail::RouteSnapshot& snapshot, unsigned index) {
    if (!valid(snapshot, index))
        return EINVAL;
    Route current[Routing::capacity];
    size_t count = 0;
    int error = list(current, Routing::capacity, count);
    if (error)
        return error;
    for (size_t at = 0; at < snapshot.size;) {
        size_t bytes = record_size(snapshot.bytes + at);
        Route original;
        if (detail::decode_route(snapshot.bytes + at, bytes, original))
            return EPROTO;
        bool present = false, conflict = false;
        for (size_t n = 0; n < count; n++) {
            if (!key(original, current[n]))
                continue;
            const auto& value = current[n];
            if (value.protocol == RTPROT_KERNEL && value.scope == RT_SCOPE_LINK && !value.gateway &&
                !value.metric && !value.tos && value.preferred_source &&
                value.destination == (value.preferred_source & value.mask))
                continue; // A new address-derived prefix is not a manual replacement.
            present |= same(original, current[n]);
            bool retained = false;
            for (size_t saved = 0; saved < snapshot.size;) {
                size_t size = record_size(snapshot.bytes + saved);
                Route value;
                if (detail::decode_route(snapshot.bytes + saved, size, value))
                    return EPROTO;
                retained |= same(value, current[n]);
                saved += size;
            }
            conflict |= !retained;
        }
        if (!present && !conflict) {
            uint8_t request[sizeof(snapshot.bytes)];
            memcpy(request, snapshot.bytes + at, bytes);
            nlmsghdr header;
            memcpy(&header, request, sizeof(header));
            // CREATE without REPLACE can restore all distinct original aliases.
            header.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE;
            memcpy(request, &header, sizeof(header));
            error = acknowledge(request, header.nlmsg_len);
            if (error && error != EEXIST)
                return error;
            if (!error && count < Routing::capacity)
                current[count++] = original;
        }
        at += bytes;
    }
    return 0;
}
} // namespace ax::net
