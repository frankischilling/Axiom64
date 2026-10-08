// SPDX-License-Identifier: GPL-3.0-or-later
#include "net/dhcp/wire.hpp"
#include <string.h>

namespace ax::dhcp {
namespace {
uint16_t get16(const uint8_t* bytes) {
    return uint16_t(bytes[0]) << 8 | bytes[1];
}

uint32_t get32(const uint8_t* bytes) {
    return uint32_t(get16(bytes)) << 16 | get16(bytes + 2);
}

void put16(uint8_t* bytes, uint16_t value) {
    bytes[0] = value >> 8;
    bytes[1] = value;
}

void put32(uint8_t* bytes, uint32_t value) {
    put16(bytes, value >> 16);
    put16(bytes + 2, value);
}

uint16_t checksum(const uint8_t* bytes, size_t size, uint32_t sum = 0) {
    while (size >= 2) {
        sum += get16(bytes);
        bytes += 2;
        size -= 2;
    }
    if (size)
        sum += uint32_t(*bytes) << 8;
    while (sum >> 16)
        sum = (sum & 65535) + (sum >> 16);
    return uint16_t(~sum);
}

uint32_t pseudo(uint32_t source, uint32_t destination, size_t size) {
    return (source >> 16) + (source & 65535) + (destination >> 16) + (destination & 65535) + 17 +
           size;
}

bool unicast(uint32_t address) {
    unsigned first = address >> 24;
    return first && first != 127 && first < 224;
}

bool mask_valid(uint32_t mask) {
    uint32_t host = ~mask;
    return !(host & (host + 1));
}

bool label_character(uint8_t value) {
    return (value >= 'a' && value <= 'z') || (value >= 'A' && value <= 'Z') ||
           (value >= '0' && value <= '9') || value == '-';
}

bool domain_name(const uint8_t* bytes, size_t size, char* output, size_t capacity) {
    if (!size || size > 253 || size >= capacity)
        return false;
    if (size == 1 && bytes[0] == '.') {
        memcpy(output, ".", 2);
        return true;
    }
    size_t label = 0;
    for (size_t i = 0; i < size; i++) {
        if (bytes[i] == '.') {
            if (!label || label > 63)
                return false;
            label = 0;
        } else if (!label_character(bytes[i]) || ++label > 63)
            return false;
    }
    if (!label && bytes[size - 1] != '.')
        return false;
    memcpy(output, bytes, size);
    output[size] = 0;
    return true;
}

struct Option {
    uint8_t code;
    bool present = false;
    size_t size = 0;
    uint8_t bytes[768]{};
};

bool scan(const uint8_t* bytes, size_t size, Option* options, size_t count, bool main) {
    size_t position = 0;
    while (position < size) {
        uint8_t code = bytes[position++];
        if (code == 255)
            return true;
        if (!code)
            continue;
        if (position == size)
            return false;
        size_t length = bytes[position++];
        if (length > size - position || (!main && code == 52))
            return false;
        for (size_t i = 0; i < count; i++) {
            auto& option = options[i];
            if (option.code != code)
                continue;
            if (length > sizeof(option.bytes) - option.size)
                return false;
            option.present = true;
            memcpy(option.bytes + option.size, bytes + position, length);
            option.size += length;
        }
        position += length;
    }
    return false;
}

bool scalar(const Option& option, bool& present, uint32_t& value) {
    present = option.present;
    if (!present)
        return true;
    if (option.size != 4)
        return false;
    value = get32(option.bytes);
    return true;
}

bool search_names(const Option& option, char* output, size_t capacity) {
    if (!option.size)
        return false;
    size_t next = 0, written = 0, names = 0;
    bool boundary[sizeof(option.bytes)]{};
    while (next < option.size) {
        if (++names > 6)
            return false;
        size_t position = next, advanced = 0, name_size = 0, steps = 0;
        bool jumped = false, first = true;
        char name[254]{};
        for (;;) {
            if (position >= option.size || ++steps > option.size)
                return false;
            boundary[position] = true;
            uint8_t length = option.bytes[position++];
            if (!jumped)
                advanced = position;
            if (!length)
                break;
            if ((length & 0xc0) == 0xc0) {
                if (position == option.size)
                    return false;
                size_t target = size_t(length & 0x3f) << 8 | option.bytes[position++];
                if (target >= position - 2 || !boundary[target])
                    return false;
                if (!jumped)
                    advanced = position;
                position = target;
                jumped = true;
                continue;
            }
            if (length > 63 || length > option.size - position ||
                name_size + length + (first ? 0 : 1) >= sizeof(name))
                return false;
            if (!first)
                name[name_size++] = '.';
            for (size_t i = 0; i < length; i++) {
                uint8_t value = option.bytes[position++];
                if (!label_character(value))
                    return false;
                name[name_size++] = value;
            }
            first = false;
            if (!jumped)
                advanced = position;
        }
        if (!name_size)
            name[name_size++] = '.';
        if (advanced <= next || written + name_size + (written ? 1 : 0) >= capacity)
            return false;
        if (written)
            output[written++] = ' ';
        memcpy(output + written, name, name_size);
        written += name_size;
        next = advanced;
    }
    output[written] = 0;
    return true;
}

bool classless_routes(const Option& option, Parameters& parameters) {
    if (!option.size)
        return false;
    parameters.classless = true;
    size_t position = 0;
    while (position < option.size) {
        unsigned prefix = option.bytes[position++];
        size_t octets = (prefix + 7) / 8;
        if (prefix > 32 || octets + 4 > option.size - position ||
            parameters.route_count == max_routes)
            return false;
        uint32_t destination = 0;
        for (size_t i = 0; i < octets; i++)
            destination |= uint32_t(option.bytes[position++]) << (24 - i * 8);
        uint32_t mask = prefix ? uint32_t(-1) << (32 - prefix) : 0;
        uint32_t gateway = get32(option.bytes + position);
        position += 4;
        if (gateway && !unicast(gateway))
            return false;
        parameters.routes[parameters.route_count++] = {destination & mask, mask, gateway};
    }
    return true;
}
} // namespace

size_t encode_message(const Request& request, void* output, size_t capacity) {
    const uint8_t zero[6]{};
    if (capacity < 300 || uint8_t(request.mode) > uint8_t(Mode::inform) ||
        (request.identity.mac[0] & 1) || !memcmp(request.identity.mac, zero, 6))
        return 0;
    if (capacity > max_payload)
        capacity = max_payload;
    auto bytes = static_cast<uint8_t*>(output);
    memset(bytes, 0, capacity);
    bytes[0] = bytes[1] = 1;
    bytes[2] = 6;
    put32(bytes + 4, request.transaction);
    put16(bytes + 8, request.seconds);
    bool configured = request.mode == Mode::renew || request.mode == Mode::rebind ||
                      request.mode == Mode::release || request.mode == Mode::inform;
    bool broadcast = request.mode == Mode::discover || request.mode == Mode::selecting ||
                     request.mode == Mode::reboot || request.mode == Mode::rebind;
    if ((configured && !unicast(request.address)) || (!configured && request.address))
        return 0;
    put16(bytes + 10, broadcast ? 0x8000 : 0);
    put32(bytes + 12, request.address);
    memcpy(bytes + 28, request.identity.mac, 6);
    put32(bytes + 236, 0x63825363);
    size_t position = 240;
    auto append = [&](uint8_t code, const void* data, size_t size) {
        if (size > 255 || position >= capacity || size + 2 > capacity - position - 1)
            return false;
        bytes[position++] = code;
        bytes[position++] = size;
        memcpy(bytes + position, data, size);
        position += size;
        return true;
    };
    Type type = request.mode == Mode::discover  ? Type::discover
                : request.mode == Mode::decline ? Type::decline
                : request.mode == Mode::release ? Type::release
                : request.mode == Mode::inform  ? Type::inform
                                                : Type::request;
    uint8_t message = uint8_t(type), client[7]{1}, value[4];
    memcpy(client + 1, request.identity.mac, 6);
    if (!append(53, &message, 1) || !append(61, client, 7))
        return 0;
    bool requested = request.mode == Mode::selecting || request.mode == Mode::reboot ||
                     request.mode == Mode::decline;
    bool server = request.mode == Mode::selecting || request.mode == Mode::decline ||
                  request.mode == Mode::release;
    if ((requested && !unicast(request.requested)) || (!requested && request.requested) ||
        (server && !unicast(request.server)) || (!server && request.server))
        return 0;
    if (requested) {
        put32(value, request.requested);
        if (!append(50, value, 4))
            return 0;
    }
    if (server) {
        put32(value, request.server);
        if (!append(54, value, 4))
            return 0;
    }
    if (request.mode != Mode::decline && request.mode != Mode::release) {
        const uint8_t all[]{1, 3, 6, 15, 51, 58, 59, 119, 121};
        const uint8_t inform[]{1, 3, 6, 15, 119, 121};
        const uint8_t maximum[]{2, 64}; // 576 octets
        bool information = request.mode == Mode::inform;
        if (!append(55, information ? inform : all, information ? sizeof(inform) : sizeof(all)) ||
            !append(57, maximum, 2))
            return 0;
    }
    size_t hostname = strnlen(request.identity.hostname, sizeof(request.identity.hostname));
    if (hostname && request.mode != Mode::decline && request.mode != Mode::release) {
        char valid[64];
        if (!domain_name(reinterpret_cast<const uint8_t*>(request.identity.hostname), hostname,
                         valid, sizeof(valid)) ||
            !append(12, valid, hostname))
            return 0;
    }
    bytes[position] = 255;
    return position + 1 < 300 ? 300 : position + 1;
}

bool decode_message(const void* input, size_t size, const Identity& identity, uint32_t transaction,
                    Reply& output) {
    if (size < 240 || size > max_payload)
        return false;
    auto bytes = static_cast<const uint8_t*>(input);
    if (bytes[0] != 2 || bytes[1] != 1 || bytes[2] != 6 || get32(bytes + 4) != transaction ||
        memcmp(bytes + 28, identity.mac, 6) || get32(bytes + 236) != 0x63825363)
        return false;
    Option options[]{{1}, {3}, {6}, {15}, {51}, {52}, {53}, {54}, {58}, {59}, {61}, {119}, {121}};
    if (!scan(bytes + 240, size - 240, options, 13, true))
        return false;
    auto& overload = options[5];
    if (overload.present) {
        if (overload.size != 1 || !overload.bytes[0] || overload.bytes[0] > 3)
            return false;
        if ((overload.bytes[0] & 1) && !scan(bytes + 108, 128, options, 13, false))
            return false;
        if ((overload.bytes[0] & 2) && !scan(bytes + 44, 64, options, 13, false))
            return false;
    }
    if (options[6].size != 1 || options[7].size != 4 ||
        (options[6].bytes[0] != 2 && options[6].bytes[0] != 5 && options[6].bytes[0] != 6))
        return false;
    auto& client = options[10];
    if (client.present &&
        (client.size != 7 || client.bytes[0] != 1 || memcmp(client.bytes + 1, identity.mac, 6)))
        return false;
    Reply result{};
    result.type = Type(options[6].bytes[0]);
    result.transaction = transaction;
    result.address = get32(bytes + 16);
    result.server = get32(options[7].bytes);
    if (!unicast(result.server))
        return false;
    auto& parameters = result.parameters;
    if (!scalar(options[0], parameters.has_mask, parameters.mask) ||
        !scalar(options[4], parameters.has_lease, parameters.lease) ||
        !scalar(options[8], parameters.has_renewal, parameters.renewal) ||
        !scalar(options[9], parameters.has_rebinding, parameters.rebinding) ||
        (parameters.has_mask && !mask_valid(parameters.mask)))
        return false;
    for (unsigned index = 1; index <= 2; index++) {
        const auto& option = options[index];
        if (!option.present)
            continue;
        if (!option.size || option.size % 4)
            return false;
        for (size_t i = 0; i < option.size; i += 4) {
            uint32_t address = get32(option.bytes + i);
            bool resolver = index == 2 && (address >> 24) == 127;
            if (!unicast(address) && !resolver)
                return false;
            if (index == 1 && !i)
                parameters.router = address;
            if (index == 2 && parameters.dns_count < max_dns)
                parameters.dns[parameters.dns_count++] = address;
        }
    }
    if ((options[3].present && !domain_name(options[3].bytes, options[3].size, parameters.domain,
                                            sizeof(parameters.domain))) ||
        (options[11].present &&
         !search_names(options[11], parameters.search, sizeof(parameters.search))) ||
        (options[12].present && !classless_routes(options[12], parameters)))
        return false;
    if (parameters.classless)
        parameters.router = 0;
    output = result;
    return true;
}

size_t encode_frame(const Request& request, uint32_t destination, const uint8_t destination_mac[6],
                    void* output, size_t capacity) {
    if (capacity < 342 || (!unicast(destination) && destination != 0xffffffff))
        return 0;
    auto bytes = static_cast<uint8_t*>(output);
    size_t size = encode_message(request, bytes + 42, capacity - 42);
    if (!size)
        return 0;
    memcpy(bytes, destination_mac, 6);
    memcpy(bytes + 6, request.identity.mac, 6);
    put16(bytes + 12, 0x0800);
    auto ip = bytes + 14, udp = bytes + 34;
    memset(ip, 0, 28);
    ip[0] = 0x45;
    put16(ip + 2, size + 28);
    put16(ip + 6, 0x4000);
    ip[8] = 64;
    ip[9] = 17;
    put32(ip + 12, request.address);
    put32(ip + 16, destination);
    put16(ip + 10, checksum(ip, 20));
    put16(udp, 68);
    put16(udp + 2, 67);
    put16(udp + 4, size + 8);
    uint16_t sum = checksum(udp, size + 8, pseudo(request.address, destination, size + 8));
    put16(udp + 6, sum ? sum : 65535);
    return size + 42;
}

bool decode_frame(const void* input, size_t size, const Identity& identity, uint32_t transaction,
                  Reply& output) {
    if (size < 282)
        return false;
    auto bytes = static_cast<const uint8_t*>(input);
    const uint8_t broadcast[]{255, 255, 255, 255, 255, 255}, zero[6]{};
    if ((memcmp(bytes, identity.mac, 6) && memcmp(bytes, broadcast, 6)) || (bytes[6] & 1) ||
        !memcmp(bytes + 6, zero, 6) || get16(bytes + 12) != 0x0800)
        return false;
    auto ip = bytes + 14;
    size_t total = get16(ip + 2);
    uint32_t source = get32(ip + 12), destination = get32(ip + 16);
    if (ip[0] != 0x45 || total < 268 || total > size - 14 || checksum(ip, 20) ||
        (get16(ip + 6) & ~uint16_t(0x4000)) || !ip[8] || ip[9] != 17 || !unicast(source) ||
        (!unicast(destination) && destination != 0xffffffff))
        return false;
    auto udp = ip + 20;
    size_t length = get16(udp + 4);
    if (get16(udp) != 67 || get16(udp + 2) != 68 || length < 248 || length > total - 20 ||
        (get16(udp + 6) && checksum(udp, length, pseudo(source, destination, length))))
        return false;
    Reply result;
    if (!decode_message(udp + 8, length - 8, identity, transaction, result))
        return false;
    result.source = source;
    result.destination = destination;
    memcpy(result.source_mac, bytes + 6, 6);
    output = result;
    return true;
}

size_t encode_arp(const Identity& identity, uint32_t address, bool announcement, void* output,
                  size_t capacity) {
    const uint8_t zero[6]{};
    if (capacity < 60 || !unicast(address) || (identity.mac[0] & 1) ||
        !memcmp(identity.mac, zero, 6))
        return 0;
    auto bytes = static_cast<uint8_t*>(output);
    memset(bytes, 0, 60);
    memset(bytes, 255, 6);
    memcpy(bytes + 6, identity.mac, 6);
    put16(bytes + 12, 0x0806);
    put16(bytes + 14, 1);
    put16(bytes + 16, 0x0800);
    bytes[18] = 6;
    bytes[19] = 4;
    put16(bytes + 20, 1);
    memcpy(bytes + 22, identity.mac, 6);
    put32(bytes + 28, announcement ? address : 0);
    put32(bytes + 38, address);
    return 60;
}

bool conflicting_arp(const void* input, size_t size, const Identity& identity, uint32_t address,
                     bool probing) {
    if (size < 42 || !unicast(address))
        return false;
    auto bytes = static_cast<const uint8_t*>(input);
    const uint8_t broadcast[]{255, 255, 255, 255, 255, 255}, zero[6]{};
    if ((memcmp(bytes, identity.mac, 6) && memcmp(bytes, broadcast, 6)) ||
        get16(bytes + 12) != 0x0806 || get16(bytes + 14) != 1 || get16(bytes + 16) != 0x0800 ||
        bytes[18] != 6 || bytes[19] != 4 || (get16(bytes + 20) != 1 && get16(bytes + 20) != 2) ||
        (bytes[22] & 1) || !memcmp(bytes + 22, zero, 6) || !memcmp(bytes + 22, identity.mac, 6) ||
        memcmp(bytes + 6, bytes + 22, 6))
        return false;
    return get32(bytes + 28) == address ||
           (probing && !get32(bytes + 28) && get32(bytes + 38) == address);
}
} // namespace ax::dhcp
