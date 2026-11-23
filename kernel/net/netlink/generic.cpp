// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/net/netlink/generic.cpp
 * @brief   Generic netlink family discovery.
 * @author  frankischilling
 * @date    2026-11-23
 *
 * Advertises the control family and handles family queries and dumps.
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
#include "net/netlink.hpp"

namespace ax {
namespace {
constexpr uint16_t control_family = 16;
constexpr uint8_t get_family = 3, new_family = 1;
constexpr uint16_t family_id = 1, family_name = 2;
constexpr char control_name[] = "nlctrl";

struct GenericHeader {
    uint8_t command, version;
    uint16_t reserved;
};

struct Attribute {
    uint16_t length, type;
};

static_assert(sizeof(GenericHeader) == 4 && sizeof(Attribute) == 4);

int select_family(const uint8_t* input, const NetlinkHeader& request, bool dump) {
    constexpr size_t header_size = sizeof(request) + sizeof(GenericHeader);
    if (request.length < header_size)
        return -22;
    GenericHeader generic{};
    memcpy(&generic, input + sizeof(request), sizeof(generic));
    if (generic.command != get_family)
        return -95;
    if (dump)
        return request.length == header_size ? 0 : -95;

    bool seen_id = false, found = false;
    const char* name = nullptr;
    for (size_t offset = header_size; offset < request.length;) {
        Attribute field{};
        size_t remaining = request.length - offset;
        if (remaining < sizeof(field))
            return -22;
        memcpy(&field, input + offset, sizeof(field));
        size_t aligned = (size_t(field.length) + 3) & ~size_t(3);
        if (field.length < sizeof(field) || aligned > remaining)
            return -22;
        size_t bytes = field.length - sizeof(field);
        const uint8_t* value = input + offset + sizeof(field);
        if (field.type == family_id && !seen_id) {
            if (bytes != sizeof(uint16_t))
                return -22;
            uint16_t id;
            memcpy(&id, value, sizeof(id));
            found = id == control_family;
            seen_id = true;
        } else if (field.type == family_name && !name) {
            if (bytes < 2 || bytes > 16 || value[bytes - 1])
                return -22;
            name = reinterpret_cast<const char*>(value);
            if (strlen(name) != bytes - 1)
                return -22;
        } else {
            return -22;
        }
        offset += aligned;
    }
    if (name)
        return strcmp(name, control_name) ? -2 : 0;
    if (!seen_id)
        return -22;
    return found ? 0 : -2;
}

void attribute(uint8_t*& tail, uint16_t type, const void* value, size_t bytes) {
    size_t size = sizeof(Attribute) + bytes;
    Attribute field{uint16_t(size), type};
    memcpy(tail, &field, sizeof(field));
    memcpy(tail + sizeof(field), value, bytes);
    size_t aligned = (size + 3) & ~size_t(3);
    memset(tail + size, 0, aligned - size);
    tail += aligned;
}

void number(uint8_t*& tail, uint16_t type, uint32_t value) {
    attribute(tail, type, &value, sizeof(value));
}

size_t describe_family(uint8_t* output, const NetlinkHeader& request, uint32_t port, bool dump) {
    // Includes the header, five scalar attributes, one operation and one group.
    static_assert(20 + 44 + 24 + 28 <= generic_family_reply_size);
    auto tail = output + sizeof(NetlinkHeader);
    const GenericHeader header{new_family, 2, 0};
    memcpy(tail, &header, sizeof(header));
    tail += sizeof(header);
    attribute(tail, family_name, control_name, sizeof(control_name));
    attribute(tail, family_id, &control_family, sizeof(control_family));
    number(tail, 3, 2); // Family version.
    number(tail, 4, 0); // No family-specific header.
    number(tail, 5, 0); // No public maxattr.

    uint8_t operation[16], entry[20];
    auto item = operation;
    number(item, 1, get_family);
    number(item, 2, 6); // GENL_CMD_CAP_DO | GENL_CMD_CAP_DUMP.
    item = entry;
    attribute(item, 1, operation, sizeof(operation));
    attribute(tail, 6, entry, sizeof(entry));

    uint8_t group[20], indexed_group[24];
    item = group;
    constexpr char notify[] = "notify";
    attribute(item, 1, notify, sizeof(notify));
    number(item, 2, control_family);
    item = indexed_group;
    attribute(item, 1, group, sizeof(group));
    attribute(tail, 7, indexed_group, sizeof(indexed_group));

    size_t length = tail - output;
    const NetlinkHeader response{uint32_t(length), control_family, uint16_t(dump ? 2 : 0),
                                 request.sequence, port};
    memcpy(output, &response, sizeof(response));
    return length;
}
} // namespace

size_t generic_reply(const void* data, uint32_t port, bool capped, void* reply, void* followup,
                     size_t& followup_length) {
    auto input = static_cast<const uint8_t*>(data);
    NetlinkHeader request;
    memcpy(&request, input, sizeof(request));
    if (!(request.flags & 1) || request.type < 16)
        return 0;
    bool dump = (request.flags & 0x300) == 0x300;
    int error = -2;
    if (request.type == control_family) {
        if (request.flags & ~(1u | 4u | (dump ? 0x300u : 0u)))
            error = -95;
        else
            error = select_family(input, request, dump);
    }
    if (error)
        return netlink_ack(input, request, port, error, capped, reply);

    if (dump) {
        const NetlinkHeader done{20, 3, 2, request.sequence, port};
        memcpy(followup, &done, sizeof(done));
        memset(static_cast<uint8_t*>(followup) + sizeof(done), 0, 4);
        followup_length = done.length;
    } else if (request.flags & 4) {
        followup_length = netlink_ack(input, request, port, 0, capped, followup);
    }
    return describe_family(static_cast<uint8_t*>(reply), request, port, dump);
}
} // namespace ax
