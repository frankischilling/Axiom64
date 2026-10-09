// SPDX-License-Identifier: GPL-3.0-or-later
#include "net/dhcp/wire.hpp"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

using namespace ax::dhcp;

static void check(bool condition, const char* message) {
    if (!condition) {
        fprintf(stderr, "DHCP_CODEC_FAIL %s\n", message);
        exit(1);
    }
}

static void put16(uint8_t* bytes, unsigned value) {
    bytes[0] = value >> 8;
    bytes[1] = value;
}

static void put32(uint8_t* bytes, uint32_t value) {
    for (unsigned i = 0; i < 4; i++)
        bytes[i] = value >> (24 - 8 * i);
}

static unsigned word(const uint8_t* bytes) {
    return unsigned(bytes[0]) * 256 + bytes[1];
}

static unsigned checksum(const uint8_t* bytes, size_t size, uint32_t sum = 0) {
    for (size_t i = 0; i < size; i += 2)
        sum += unsigned(bytes[i]) * 256 + (i + 1 < size ? bytes[i + 1] : 0);
    while (sum > 65535)
        sum = (sum & 65535) + (sum >> 16);
    return sum ^ 65535;
}

static Identity identity{{0x52, 0x54, 0, 0x12, 0x34, 0x10}, "axiom64"};
constexpr uint32_t transaction = 0x12345678;

struct Fixture {
    uint8_t bytes[1024]{};
    size_t size = 240;

    Fixture() {
        bytes[0] = 2;
        bytes[1] = 1;
        bytes[2] = 6;
        put32(bytes + 4, transaction);
        put32(bytes + 16, 0x0a170128);
        memcpy(bytes + 28, identity.mac, 6);
        put32(bytes + 236, 0x63825363);
    }

    void option(unsigned code, const void* data, size_t length) {
        check(length <= 255 && size + length + 3 <= sizeof(bytes), "fixture option bounds");
        bytes[size++] = code;
        bytes[size++] = length;
        memcpy(bytes + size, data, length);
        size += length;
    }

    void integer(unsigned code, uint32_t value) {
        uint8_t bytes[4];
        put32(bytes, value);
        option(code, bytes, 4);
    }

    void required(unsigned type = 5) {
        uint8_t value = type;
        option(53, &value, 1);
        integer(54, 0x0a170101);
    }

    void end() {
        bytes[size++] = 255;
    }
};

static bool decode(const Fixture& fixture, Reply& reply) {
    return decode_message(fixture.bytes, fixture.size, identity, transaction, reply);
}

static void invalid(const Fixture& fixture, const char* message) {
    Reply reply{};
    reply.server = 0xabcdef01;
    Reply original = reply;
    check(!decode(fixture, reply) && !memcmp(&reply, &original, sizeof(reply)), message);
}

static void parameters(void) {
    Fixture fixture;
    fixture.required();
    fixture.integer(1, 0xffffff00);
    fixture.integer(3, 0x0a170101);
    const uint8_t dns[]{10, 23, 1, 53, 10, 23, 1, 54, 10, 23, 1, 55, 10, 23, 1, 56};
    fixture.option(6, dns, sizeof(dns));
    fixture.option(15, "lab.example", 11);
    fixture.integer(51, 60);
    fixture.integer(58, 30);
    fixture.integer(59, 52);
    fixture.end();
    Reply reply;
    check(decode(fixture, reply) && reply.type == Type::ack && reply.transaction == transaction &&
              reply.address == 0x0a170128 && reply.server == 0x0a170101 &&
              reply.parameters.has_mask && reply.parameters.mask == 0xffffff00 &&
              reply.parameters.router == 0x0a170101 && reply.parameters.dns_count == 3 &&
              reply.parameters.dns[0] == 0x0a170135 && reply.parameters.dns[2] == 0x0a170137 &&
              !strcmp(reply.parameters.domain, "lab.example") && reply.parameters.has_lease &&
              reply.parameters.lease == 60 && reply.parameters.has_renewal &&
              reply.parameters.renewal == 30 && reply.parameters.has_rebinding &&
              reply.parameters.rebinding == 52,
          "owned ACK parameters and bounded resolver list");
    for (size_t size = 0; size < fixture.size; size++) {
        Reply output{};
        check(!decode_message(fixture.bytes, size, identity, transaction, output),
              "every truncated ACK rejected");
    }
    const unsigned offsets[]{0, 1, 2, 4, 28, 236};
    for (unsigned offset : offsets) {
        Fixture broken = fixture;
        broken.bytes[offset] ^= 0x40;
        invalid(broken, "BOOTP identity, transaction, or cookie rejected");
    }
    memset(fixture.bytes, 0xa5, sizeof(fixture.bytes));
    check(!strcmp(reply.parameters.domain, "lab.example") && reply.parameters.dns[1] == 0x0a170136,
          "reply snapshots do not borrow receive bytes");
    puts("DHCP_CODEC_PARAMETERS_PASS");
}

static void options(void) {
    Fixture missing;
    missing.end();
    invalid(missing, "missing type and server rejected");
    Fixture duplicate;
    duplicate.required();
    const uint8_t type = 5;
    duplicate.option(53, &type, 1);
    duplicate.end();
    invalid(duplicate, "concatenated singleton cannot become a valid scalar");
    Fixture mask;
    mask.required();
    mask.integer(1, 0xff00ff00);
    mask.end();
    invalid(mask, "noncontiguous subnet mask rejected");
    Fixture short_option;
    short_option.required();
    const uint8_t short_integer[]{1, 2, 3};
    short_option.option(51, short_integer, 3);
    short_option.end();
    invalid(short_option, "incorrect typed option length rejected");
    Fixture injected;
    injected.required();
    injected.option(15, "lab\nnameserver 1.2.3.4", 22);
    injected.end();
    invalid(injected, "resolver line injection rejected");
    Fixture client;
    client.required();
    const uint8_t wrong[]{1, 0x52, 0x54, 0, 0x12, 0x34, 0x11};
    client.option(61, wrong, sizeof(wrong));
    client.end();
    invalid(client, "unrelated echoed client identifier rejected");
    Fixture unknown;
    unknown.required(6);
    uint8_t data[255];
    memset(data, 0x37, sizeof(data));
    unknown.option(200, data, sizeof(data));
    unknown.end();
    Reply reply;
    check(decode(unknown, reply) && reply.type == Type::nak && !reply.parameters.has_lease,
          "bounded unknown option skipped and NAK has no fabricated lease");
    puts("DHCP_CODEC_OPTIONS_PASS");
}

static void overload(void) {
    const uint8_t search[]{3,   'l', 'a', 'b', 7,   'e', 'x', 'a', 'm',  'p',
                           'l', 'e', 0,   4,   'm', 'a', 'i', 'l', 0xc0, 4};
    Fixture fixture;
    fixture.required();
    uint8_t flag = 3;
    fixture.option(52, &flag, 1);
    fixture.option(119, search, 7);
    fixture.end();
    fixture.bytes[108] = 119;
    fixture.bytes[109] = 6;
    memcpy(fixture.bytes + 110, search + 7, 6);
    fixture.bytes[116] = 255;
    fixture.bytes[44] = 119;
    fixture.bytes[45] = 7;
    memcpy(fixture.bytes + 46, search + 13, 7);
    fixture.bytes[53] = 255;
    Reply reply;
    check(decode(fixture, reply) && !strcmp(reply.parameters.search, "lab.example mail.example"),
          "main/file/sname concatenation precedes compressed search decoding");
    Fixture broken = fixture;
    broken.bytes[51] = 0xc0;
    broken.bytes[52] = 18;
    invalid(broken, "self-referencing compressed name rejected");
    broken = fixture;
    broken.bytes[116] = 0;
    invalid(broken, "overloaded option area requires an end marker");
    broken = fixture;
    broken.bytes[108] = 52;
    invalid(broken, "nested overload rejected");
    puts("DHCP_CODEC_OVERLOAD_SEARCH_PASS");
}

static void routes(void) {
    Fixture fixture;
    fixture.required();
    fixture.integer(3, 0x0a170109);
    const uint8_t routes[]{0, 10, 23, 1, 1, 16, 172, 20, 10, 23, 1, 3, 9, 172, 255, 0, 0, 0, 0};
    fixture.option(121, routes, sizeof(routes));
    fixture.end();
    Reply reply;
    check(decode(fixture, reply) && reply.parameters.classless && !reply.parameters.router &&
              reply.parameters.route_count == 3 && reply.parameters.routes[0].destination == 0 &&
              reply.parameters.routes[0].mask == 0 &&
              reply.parameters.routes[0].gateway == 0x0a170101 &&
              reply.parameters.routes[1].destination == 0xac140000 &&
              reply.parameters.routes[1].mask == 0xffff0000 &&
              reply.parameters.routes[2].destination == 0xac800000 &&
              reply.parameters.routes[2].mask == 0xff800000 &&
              reply.parameters.routes[2].gateway == 0,
          "classless route widths, canonical prefixes, on-link route, and router precedence");
    Fixture broken;
    broken.required();
    const uint8_t bad[]{33, 1, 2, 3, 4};
    broken.option(121, bad, sizeof(bad));
    broken.end();
    invalid(broken, "invalid route prefix rejected before shifting");
    broken = Fixture{};
    broken.required();
    uint8_t many[(max_routes + 1) * 5]{};
    for (size_t i = 0; i < max_routes + 1; i++) {
        many[i * 5 + 1] = 10;
        many[i * 5 + 2] = 23;
        many[i * 5 + 3] = 1;
        many[i * 5 + 4] = 1;
    }
    broken.option(121, many, sizeof(many));
    broken.end();
    invalid(broken, "route capacity enforced without a partial reply");
    puts("DHCP_CODEC_ROUTES_PASS");
}

static void search_boundaries(void) {
    Fixture fixture;
    fixture.required();
    fixture.option(15, "lab.example.", 12);
    const uint8_t roots[]{0, 1, 'x', 0, 0xc0, 0};
    fixture.option(119, roots, sizeof(roots));
    fixture.end();
    Reply reply;
    check(decode(fixture, reply) && !strcmp(reply.parameters.domain, "lab.example.") &&
              !strcmp(reply.parameters.search, ". x ."),
          "absolute domain and compressed root search entries are safe resolver text");
    fixture = Fixture{};
    fixture.required();
    fixture.option(15, ".", 1);
    fixture.end();
    check(decode(fixture, reply) && !strcmp(reply.parameters.domain, "."),
          "root domain is represented explicitly");
    Fixture broken;
    broken.required();
    uint8_t interior[54]{};
    interior[0] = 50;
    interior[1] = '1';
    memset(interior + 2, 'a', 49);
    interior[52] = 0xc0;
    interior[53] = 1;
    broken.option(119, interior, sizeof(interior));
    broken.end();
    invalid(broken, "compression pointer cannot reinterpret literal label bytes");
    puts("DHCP_CODEC_SEARCH_BOUNDARIES_PASS");
}

static const uint8_t* find(const uint8_t* bytes, size_t size, unsigned code, size_t& length) {
    size_t position = 240;
    while (position < size && bytes[position] != 255) {
        unsigned candidate = bytes[position++];
        if (!candidate)
            continue;
        check(position < size, "request option header bounds");
        length = bytes[position++];
        check(length <= size - position, "request option data bounds");
        if (candidate == code)
            return bytes + position;
        position += length;
    }
    return nullptr;
}

static void encoding(void) {
    const Mode modes[]{Mode::discover, Mode::selecting, Mode::reboot,  Mode::renew,
                       Mode::rebind,   Mode::decline,   Mode::release, Mode::inform};
    for (auto mode : modes) {
        Request request;
        request.identity = identity;
        request.mode = mode;
        request.transaction = transaction;
        request.seconds = 0x1234;
        bool configured = mode == Mode::renew || mode == Mode::rebind || mode == Mode::release ||
                          mode == Mode::inform;
        bool selected = mode == Mode::selecting || mode == Mode::decline;
        if (configured)
            request.address = 0x0a170128;
        if (selected || mode == Mode::reboot)
            request.requested = 0x0a170128;
        if (selected || mode == Mode::release)
            request.server = 0x0a170101;
        uint8_t bytes[576];
        size_t size = encode_message(request, bytes, sizeof(bytes)), length = 0;
        check(size >= 300 && size <= sizeof(bytes) && bytes[0] == 1 && bytes[1] == 1 &&
                  bytes[2] == 6 && word(bytes + 8) == 0x1234 &&
                  !memcmp(bytes + 28, identity.mac, 6),
              "request BOOTP identity, elapsed time, and minimum padding");
        const auto server = find(bytes, size, 54, length);
        check(bool(server) == (selected || mode == Mode::release) && (!server || length == 4),
              "server identifier follows selecting/decline/release policy");
        check(bool(find(bytes, size, 50, length)) == (selected || mode == Mode::reboot),
              "requested-address option follows selecting/reboot/decline policy");
        check(bool(find(bytes, size, 55, length)) ==
                  (mode != Mode::decline && mode != Mode::release),
              "decline and release do not carry a parameter request list");
        if (const auto list = find(bytes, size, 55, length)) {
            size_t classless = length, router = length;
            for (size_t i = 0; i < length; i++) {
                if (list[i] == 121)
                    classless = i;
                if (list[i] == 3)
                    router = i;
            }
            check(classless < router && router < length,
                  "RFC 3442 classless route request precedes Router in every request mode");
        }
        check(bool(find(bytes, size, 12, length)) ==
                      (mode != Mode::decline && mode != Mode::release) &&
                  word(bytes + 10) == (mode == Mode::discover || mode == Mode::selecting ||
                                               mode == Mode::reboot || mode == Mode::rebind
                                           ? 0x8000
                                           : 0),
              "broadcast-reply flags and decline/release option restrictions");
        const auto identifier = find(bytes, size, 61, length);
        check(identifier && length == 7 && identifier[0] == 1 &&
                  !memcmp(identifier + 1, identity.mac, 6),
              "stable Ethernet client identifier in every transaction");
    }
    Request request;
    request.identity = identity;
    request.transaction = transaction;
    memset(request.identity.hostname, 'h', 63);
    request.identity.hostname[63] = 0;
    uint8_t bytes[576];
    check(encode_message(request, bytes, sizeof(bytes)) > 300,
          "maximum hostname is not restricted by minimum BOOTP padding");
    request.identity = identity;
    const uint8_t broadcast[]{255, 255, 255, 255, 255, 255};
    size_t size = encode_frame(request, 0xffffffff, broadcast, bytes, sizeof(bytes));
    check(size == 342 && !memcmp(bytes, broadcast, 6) && !memcmp(bytes + 6, identity.mac, 6) &&
              word(bytes + 12) == 0x0800 && word(bytes + 16) == 328 && bytes[22] == 64 &&
              bytes[23] == 17 && checksum(bytes + 14, 20) == 0 && word(bytes + 34) == 68 &&
              word(bytes + 36) == 67 && word(bytes + 38) == 308 && word(bytes + 40) &&
              checksum(bytes + 34, 308, 65535 + 65535 + 17 + 308) == 0,
          "initial source-zero broadcast Ethernet/IP/UDP frame has an independent checksum");
    puts("DHCP_CODEC_ENCODING_PASS");
}

static void frame(void) {
    Fixture fixture;
    fixture.required();
    fixture.integer(51, 60);
    fixture.end();
    uint8_t packet[1536]{};
    const uint8_t peer[]{2, 0x41, 0x58, 0x44, 0x48, 0};
    memcpy(packet, identity.mac, 6);
    memcpy(packet + 6, peer, 6);
    put16(packet + 12, 0x0800);
    packet[14] = 0x45;
    packet[22] = 61;
    packet[23] = 17;
    put16(packet + 16, fixture.size + 28);
    put32(packet + 26, 0x0a170101);
    put32(packet + 30, 0xffffffff);
    put16(packet + 24, checksum(packet + 14, 20));
    put16(packet + 34, 67);
    put16(packet + 36, 68);
    put16(packet + 38, fixture.size + 8);
    memcpy(packet + 42, fixture.bytes, fixture.size);
    uint32_t pseudo = 0x0a17 + 0x0101 + 65535 + 65535 + 17 + fixture.size + 8;
    put16(packet + 40, checksum(packet + 34, fixture.size + 8, pseudo));
    Reply reply;
    check(decode_frame(packet, fixture.size + 42, identity, transaction, reply) &&
              reply.source == 0x0a170101 && reply.destination == 0xffffffff &&
              !memcmp(reply.source_mac, peer, 6),
          "independently built server frame and owned transport metadata");
    packet[40] = packet[41] = 0;
    check(decode_frame(packet, fixture.size + 42, identity, transaction, reply),
          "zero IPv4 UDP checksum accepted for a DHCP server");
    packet[40] = 0x37;
    check(!decode_frame(packet, fixture.size + 42, identity, transaction, reply),
          "incorrect UDP checksum rejected");
    packet[40] = 0;
    packet[14] = 0x46;
    check(!decode_frame(packet, fixture.size + 42, identity, transaction, reply),
          "unsupported IPv4 options rejected");
    puts("DHCP_CODEC_FRAME_PASS");
}

static void arp(void) {
    uint8_t bytes[60];
    constexpr uint32_t address = 0x0a170128;
    check(encode_arp(identity, address, false, bytes, sizeof(bytes)) == 60 &&
              word(bytes + 12) == 0x0806 && word(bytes + 14) == 1 && word(bytes + 16) == 0x0800 &&
              bytes[18] == 6 && bytes[19] == 4 && word(bytes + 20) == 1 &&
              !memcmp(bytes + 22, identity.mac, 6) && !memcmp(bytes + 28, "\0\0\0\0", 4) &&
              !memcmp(bytes + 32, "\0\0\0\0\0\0", 6) && word(bytes + 38) == 0x0a17 &&
              word(bytes + 40) == 0x0128,
          "source-zero candidate probe has independent Ethernet/ARP field checks");
    check(!conflicting_arp(bytes, 60, identity, address, true), "own reflected probes ignored");
    Identity peer{{2, 0x41, 0x58, 0x44, 0x48, 0}, "peer"};
    check(encode_arp(peer, address, false, bytes, sizeof(bytes)) == 60 &&
              conflicting_arp(bytes, 60, identity, address, true) &&
              !conflicting_arp(bytes, 60, identity, address, false),
          "simultaneous candidate probe conflicts only while probing");
    check(encode_arp(peer, address, true, bytes, sizeof(bytes)) == 60 &&
              conflicting_arp(bytes, 60, identity, address, false),
          "claimed address conflicts after binding");
    for (size_t size = 0; size < 42; size++)
        check(!conflicting_arp(bytes, size, identity, address, true), "truncated ARP ignored");
    const size_t fields[]{12, 14, 16, 18, 19, 20, 22};
    for (size_t field : fields) {
        uint8_t original = bytes[field];
        bytes[field] ^= 1;
        check(!conflicting_arp(bytes, 60, identity, address, true), "malformed ARP ignored");
        bytes[field] = original;
    }
    bytes[6] ^= 2;
    check(!conflicting_arp(bytes, 60, identity, address, true), "ARP and Ethernet source agree");
    puts("DHCP_CODEC_ARP_PASS");
}

static void mutations(void) {
    Fixture fixture;
    fixture.required();
    fixture.integer(51, 60);
    fixture.end();
    uint32_t random = 0x5041434b;
    for (unsigned i = 0; i < 12000; i++) {
        Fixture changed = fixture;
        random ^= random << 13;
        random ^= random >> 17;
        random ^= random << 5;
        changed.bytes[random % changed.size] ^= uint8_t((random >> 8) | 1);
        Reply reply;
        if (decode(changed, reply))
            check(reply.transaction == transaction && reply.parameters.route_count <= max_routes &&
                      reply.parameters.dns_count <= max_dns,
                  "mutated input cannot escape reply identity or capacities");
    }
    puts("DHCP_CODEC_MUTATIONS_PASS count=12000");
}

int main() {
    parameters();
    options();
    overload();
    routes();
    search_boundaries();
    encoding();
    frame();
    arp();
    mutations();
    puts("DHCP_CODEC_TESTS_PASS");
    return 0;
}
