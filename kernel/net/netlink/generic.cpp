// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/net/netlink/generic.cpp
 * @brief   Generic Netlink controller family discovery.
 * @author  frankischilling
 * @date    2026-11-23
 *
 * Copyright (C) 2026 frankischilling
 */
#include "net/netlink.hpp"

namespace ax {
namespace {
struct GenericHeader {
    uint8_t command, version;
    uint16_t reserved;
};

struct Attribute {
    uint16_t length, type;
};

constexpr uint16_t controller_id = 16, request_flag = 1, multi_flag = 2, ack_flag = 4,
                   dump_flags = 0x300, done_type = 3;
constexpr uint8_t new_family = 1, get_family = 3;
constexpr uint32_t controller_version = 2, operation_flags = 0x0e;
constexpr char controller_name[] = "nlctrl";
constexpr uint16_t family_id = 1, family_name = 2, version = 3, header_size = 4, max_attribute = 5,
                   operations = 6, operation_id = 1, operation_capabilities = 2;
constexpr size_t header_bytes = sizeof(NetlinkHeader) + sizeof(GenericHeader);
constexpr size_t operation_bytes = sizeof(Attribute) + 2 * netlink_align(sizeof(Attribute) + 4);
constexpr size_t family_bytes =
    header_bytes + netlink_align(sizeof(Attribute) + sizeof(controller_name)) +
    netlink_align(sizeof(Attribute) + sizeof(controller_id)) +
    3 * netlink_align(sizeof(Attribute) + sizeof(uint32_t)) + sizeof(Attribute) + operation_bytes;
constexpr size_t success_ack_bytes = sizeof(NetlinkHeader) * 2 + sizeof(int32_t);
constexpr size_t done_bytes = sizeof(NetlinkHeader) + sizeof(int32_t);
static_assert(sizeof(GenericHeader) == 4 && sizeof(Attribute) == 4);
static_assert(done_bytes <= success_ack_bytes);

void put_attribute(uint8_t* output, size_t& at, uint16_t type, const void* data, size_t bytes) {
    const Attribute attribute{uint16_t(sizeof(Attribute) + bytes), type};
    const size_t next = netlink_align(attribute.length);
    memcpy(output + at, &attribute, sizeof(attribute));
    memcpy(output + at + sizeof(attribute), data, bytes);
    memset(output + at + attribute.length, 0, next - attribute.length);
    at += next;
}

// The controller uses the last ID and name attributes, with the name taking precedence.
int find_controller(const uint8_t* input, size_t length) {
    bool has_id = false, has_name = false, known_name = false;
    uint16_t id = 0;
    for (size_t at = header_bytes; length - at >= sizeof(Attribute);) {
        Attribute field;
        memcpy(&field, input + at, sizeof(field));
        if (field.length < sizeof(field) || field.length > length - at)
            return -22;
        const auto* data = input + at + sizeof(field);
        const auto bytes = field.length - sizeof(field);
        switch (field.type & 0x3fff) {
        case family_id:
            if (bytes < sizeof(id))
                return -34;
            memcpy(&id, data, sizeof(id));
            has_id = true;
            break;
        case family_name: {
            if (!bytes || bytes > 16)
                return -22;
            size_t name_bytes = 0;
            while (name_bytes < bytes && data[name_bytes])
                ++name_bytes;
            if (name_bytes == bytes)
                return -22;
            has_name = true;
            known_name = name_bytes == sizeof(controller_name) - 1 &&
                         !memcmp(data, controller_name, name_bytes);
            break;
        }
        }
        const size_t next = netlink_align(field.length);
        if (next > length - at)
            break;
        at += next;
    }
    if (has_name)
        return known_name ? 0 : -2;
    if (has_id)
        return id == controller_id ? 0 : -2;
    return -22;
}

size_t describe_controller(const NetlinkHeader& request, uint32_t port, bool dump,
                           uint8_t* output) {
    const NetlinkHeader header{family_bytes, controller_id, uint16_t(dump ? multi_flag : 0),
                               request.sequence, port};
    const GenericHeader generic{new_family, uint8_t(controller_version), 0};
    memcpy(output, &header, sizeof(header));
    memcpy(output + sizeof(header), &generic, sizeof(generic));
    size_t at = header_bytes;
    put_attribute(output, at, family_name, controller_name, sizeof(controller_name));
    put_attribute(output, at, family_id, &controller_id, sizeof(controller_id));
    put_attribute(output, at, version, &controller_version, sizeof(controller_version));
    const uint32_t zero = 0, get_operation = get_family;
    put_attribute(output, at, header_size, &zero, sizeof(zero));
    put_attribute(output, at, max_attribute, &zero, sizeof(zero));

    // Controller attributes use legacy nested arrays without the nested flag.
    uint8_t entry[operation_bytes]{};
    const Attribute op{operation_bytes, 1};
    memcpy(entry, &op, sizeof(op));
    size_t op_at = sizeof(op);
    put_attribute(entry, op_at, operation_id, &get_operation, sizeof(get_operation));
    put_attribute(entry, op_at, operation_capabilities, &operation_flags, sizeof(operation_flags));
    put_attribute(output, at, operations, entry, sizeof(entry));

    if (dump) {
        const NetlinkHeader done{done_bytes, done_type, multi_flag, request.sequence, port};
        memcpy(output + at, &done, sizeof(done));
        memcpy(output + at + sizeof(done), &zero, sizeof(zero));
        at += done_bytes;
    }
    return at;
}
} // namespace

size_t generic_netlink_capacity(const NetlinkHeader& request, bool capped) {
    const size_t error_capacity = capped ? success_ack_bytes : 20 + netlink_align(request.length);
    return max(error_capacity, family_bytes + success_ack_bytes);
}

size_t generic_netlink_reply(const void* packet, uint32_t port, bool capped, void* reply) {
    const auto* input = static_cast<const uint8_t*>(packet);
    auto* output = static_cast<uint8_t*>(reply);
    NetlinkHeader request;
    memcpy(&request, input, sizeof(request));
    if (!(request.flags & request_flag) || request.type < controller_id)
        return 0;
    const bool dump = (request.flags & dump_flags) == dump_flags;
    int error = -2;
    if (request.type == controller_id) {
        if (request.length < header_bytes) {
            error = -22;
        } else {
            GenericHeader generic;
            memcpy(&generic, input + sizeof(request), sizeof(generic));
            error = generic.command != get_family ? -95
                    : dump                        ? 0
                                                  : find_controller(input, request.length);
        }
    }
    if (error)
        return netlink_ack(packet, request, port, capped, error, output);
    const size_t size = describe_controller(request, port, dump, output);
    if (!dump && (request.flags & ack_flag))
        return size + netlink_ack(packet, request, port, capped, 0, output + size);
    return size;
}
} // namespace ax
