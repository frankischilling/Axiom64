// SPDX-License-Identifier: GPL-3.0-or-later
#include "net/ipv4/options.hpp"
#include <array>
#include <cassert>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

using ax::ip4::OptionPolicy;
using ax::ip4::Options;

static std::vector<uint8_t> decode(const std::string& text) {
    if (text == "-")
        return {};
    assert(text.size() % 2 == 0);
    std::vector<uint8_t> bytes;
    for (size_t index = 0; index < text.size(); index += 2)
        bytes.push_back(uint8_t(std::stoul(text.substr(index, 2), nullptr, 16)));
    return bytes;
}

static void output_rules() {
    const uint8_t record[]{7, 7, 4, 99, 98, 97, 96};
    Options options;
    assert(!options.assign(record, sizeof(record)));
    const uint8_t normalized[]{7, 7, 4, 0, 0, 0, 0, 0};
    assert(options.size() == sizeof(normalized));
    assert(!memcmp(options.data(), normalized, sizeof(normalized)));
    std::array<uint8_t, 48> output;
    output.fill(0xa5);
    assert(options.emit(output.data(), 7, 0xc0000201, 0x0a00020f, 12345) == -105);
    for (auto byte : output)
        assert(byte == 0xa5);
    assert(options.emit(output.data(), 40, 0xc0000201, 0x0a00020f, 12345) == 8);
    const uint8_t recorded[]{7, 7, 8, 10, 0, 2, 15, 0};
    assert(!memcmp(output.data(), recorded, sizeof(recorded)));
    assert(output[8] == 0xa5 && !memcmp(options.data(), normalized, sizeof(normalized)));

    const uint8_t stamp[]{68, 12, 5, 1, 99, 98, 97, 96, 95, 94, 93, 92};
    assert(!options.assign(stamp, sizeof(stamp)));
    assert(options.emit(output.data(), 40, 0xc0000201, 0x0a00020f, 12345) == 12);
    const uint8_t stamped[]{68, 12, 13, 1, 10, 0, 2, 15, 0, 0, 48, 57};
    assert(!memcmp(output.data(), stamped, sizeof(stamped)));
    const uint8_t stamp_query[]{68, 12, 5, 1, 0, 0, 0, 0, 0, 0, 0, 0};
    assert(!memcmp(options.data(), stamp_query, sizeof(stamp_query)));

    const uint8_t route[]{131, 11, 4, 192, 0, 2, 1, 198, 51, 100, 1};
    assert(!options.assign(route, sizeof(route), {true}));
    assert(options.source_route() && !options.strict_route());
    assert(options.destination(0xcb007101) == 0xc0000201);
    assert(options.emit(output.data(), 40, 0xcb007101, 0x0a00020f, 12345) == 12);
    const uint8_t routed[]{131, 11, 4, 198, 51, 100, 1, 203, 0, 113, 1, 0};
    assert(!memcmp(output.data(), routed, sizeof(routed)));
    Options retained = options;
    assert(!options.assign(nullptr, 0));
    assert(!options.size() && !options.source_route() &&
           options.destination(0xcb007101) == 0xcb007101);
    assert(retained.emit(output.data(), 40, 0xcb007101, 0x0a00020f, 12345) == 12);
    assert(!memcmp(output.data(), routed, sizeof(routed)));
    assert(retained.assign(route, 41) == -22 && retained.assign(nullptr, 1) == -22);
    assert(retained.destination(0xcb007101) == 0xc0000201);
}

static void failure_ownership() {
    const uint8_t route[]{137, 11, 4, 192, 0, 2, 1, 198, 51, 100, 1};
    uint32_t random = 0x9713a65b;
    for (unsigned attempt = 0; attempt < 20000; attempt++) {
        std::array<uint8_t, 40> input;
        for (auto& byte : input) {
            random ^= random << 13;
            random ^= random >> 17;
            random ^= random << 5;
            byte = uint8_t(random);
        }
        Options value;
        assert(!value.assign(route, sizeof(route), {true}));
        Options before = value;
        int result = value.assign(input.data(), attempt % 41, {bool(attempt & 1)});
        if (result) {
            assert((result == -22 || result == -1) && value.size() == before.size());
            assert(!memcmp(value.data(), before.data(), before.size()));
            assert(value.source_route() && value.strict_route());
            assert(value.destination(0xcb007101) == before.destination(0xcb007101));
            std::array<uint8_t, 40> first{}, second{};
            assert(value.emit(first.data(), first.size(), 0xcb007101, 0x0a00020f, 12345) ==
                   before.emit(second.data(), second.size(), 0xcb007101, 0x0a00020f, 12345));
            assert(first == second);
        } else {
            assert(value.size() <= 40 && value.size() % 4 == 0);
            std::array<uint8_t, 48> frame;
            frame.fill(0xa5);
            assert(value.emit(frame.data(), 40, 0xcb007101, 0x0a00020f, 12345) ==
                   int(value.size()));
            for (size_t at = value.size(); at < frame.size(); at++)
                assert(frame[at] == 0xa5);
        }
        ax::ip4::ReceivedOptions received;
        if (!received.assign(input.data(), (attempt % 11) * 4, 0xc0000201, 0x0a00020f, 12345) &&
            received.return_valid()) {
            std::array<uint8_t, 48> frame;
            frame.fill(0xa5);
            assert(received.reply().size() <= 40);
            assert(received.reply().emit(frame.data(), 40, 0xc0000201, 0x0a00020f, 12345) ==
                   int(received.reply().size()));
            for (size_t at = received.reply().size(); at < frame.size(); at++)
                assert(frame[at] == 0xa5);
        }
    }
}

static void source_route_permissions() {
    for (uint8_t kind : {uint8_t(131), uint8_t(137)}) {
        uint8_t route[]{kind, 7, 4, 192, 0, 2, 1, 0};
        const uint8_t seed[]{1, 1, 1, 1};
        Options value;
        assert(!value.assign(seed, sizeof(seed)));
        assert(value.assign(route, sizeof(route)) == -1);
        assert(value.size() == sizeof(seed) && !memcmp(value.data(), seed, sizeof(seed)));
        assert(!value.source_route() && value.destination(0xc6336401) == 0xc6336401);
        // Syntax across the whole value precedes the source-route capability
        // decision. Failed syntax and permission checks retain the old value.
        route[7] = 2;
        assert(value.assign(route, sizeof(route)) == -22);
        route[7] = 0;
        route[2] = 5;
        assert(value.assign(route, sizeof(route)) == -22);
        route[2] = 4;
        assert(value.size() == sizeof(seed) && !memcmp(value.data(), seed, sizeof(seed)));
        assert(!value.assign(route, sizeof(route), {true}));
        Options before = value;
        assert(value.assign(route, sizeof(route)) == -1);
        assert(value.size() == before.size() &&
               !memcmp(value.data(), before.data(), before.size()));
        assert(value.source_route() && value.destination(0xc6336401) == 0xc0000201);
        assert(!value.assign(nullptr, 0));
        assert(!value.size() && !value.source_route());
    }
}

static int receive_rules() {
    std::string name, input, processed, returned;
    int expected_result, parameter;
    unsigned valid;
    uint32_t timestamp;
    size_t observations = 0;
    while (std::cin >> name >> input >> expected_result >> processed >> valid >> returned >>
           timestamp >> parameter) {
        auto bytes = decode(input), expected = decode(processed), reply = decode(returned);
        ax::ip4::ReceivedOptions value;
        int result = value.assign(bytes.data(), bytes.size(), 0x7f000002, 0x7f000001, timestamp);
        if (result != expected_result ||
            (result && parameter >= 0 && value.parameter() != parameter) ||
            (!result &&
             (value.size() != expected.size() ||
              (!expected.empty() && memcmp(value.data(), expected.data(), expected.size())) ||
              value.return_valid() != bool(valid) ||
              (valid &&
               (value.reply().size() != reply.size() ||
                (!reply.empty() && memcmp(value.reply().data(), reply.data(), reply.size()))))))) {
            std::cerr << "native receive option mismatch: " << name << " result=" << result
                      << " expected=" << expected_result
                      << " parameter=" << unsigned(value.parameter())
                      << " expected_parameter=" << parameter
                      << " return_valid=" << value.return_valid() << " expected_valid=" << valid
                      << '\n';
            return 1;
        }
        observations++;
    }
    assert(std::cin.eof() && observations > 200);
    failure_ownership();
    std::cout << "IPV4_OPTIONS_RECEIVE_HOST_PASS native_observations=" << observations
              << " mutation_cases=20000\n";
    return 0;
}

static bool local_hop(uint32_t address) {
    return address == 0x0a000001 || address == 0x0a010001;
}

static void received_routes() {
    using ax::ip4::ReceivedOptions;
    const uint8_t route[] = {131, 15, 4, 10, 0, 0, 1, 10, 1, 0, 1, 10, 1, 0, 2, 0};
    ReceivedOptions value;
    assert(!value.assign(route, sizeof(route), 0x0a000002, 0x0a000001, 12345));
    assert(value.source_route() && !value.strict_route());
    uint32_t destination = 0x0a000001, next = 0;
    assert(value.route(destination, next, local_hop) == 1 && destination == 0x0a010001 &&
           next == 0x0a010002);
    assert(!memcmp(value.data(), route, sizeof(route)));
    auto returned = value.reply();
    value.forward(0x0a010001);
    const uint8_t advanced[] = {131, 15, 16, 10, 0, 0, 1, 10, 1, 0, 1, 10, 1, 0, 1, 0};
    assert(!memcmp(value.data(), advanced, sizeof(advanced)));
    assert(value.reply().size() == returned.size() &&
           !memcmp(value.reply().data(), returned.data(), returned.size()));
    destination = 0x0a000001;
    assert(!value.route(destination, next, local_hop) && !next && destination == 0x0a000001);
    const uint8_t exhausted[] = {137, 7, 8, 10, 1, 0, 2, 0};
    assert(!value.assign(exhausted, sizeof(exhausted), 0x0a000002, 0x0a000001, 12345));
    assert(value.strict_route() && !value.route(destination, next, local_hop));
    assert(value.reply().source_route() && value.reply().destination(0x0a000002) == 0x0a010002);
    const uint8_t partial[] = {131, 7, 5, 10, 1, 0, 2, 0};
    assert(!value.assign(partial, sizeof(partial), 0x0a000002, 0x0a000001, 12345));
    assert(value.route(destination, next, local_hop) == -22 && value.parameter() == 22);
    const uint8_t zero[] = {131, 7, 4, 0, 0, 0, 0, 0};
    assert(!value.assign(zero, sizeof(zero), 0x0a000002, 0x0a000001, 12345));
    assert(value.route(destination, next, local_hop) == 1 && next == 0);
    const uint8_t combined[] = {131, 7,  4, 10, 1, 0, 2, 7, 7, 4, 0, 0, 0, 0,
                                68,  12, 5, 1,  0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    assert(!value.assign(combined, sizeof(combined), 0x0a000002, 0x0a000001, 12345));
    assert(value.route(destination, next, local_hop) == 1 && next == 0x0a010002);
    auto before = value;
    value.forward(0x0a010001);
    assert(value.data()[2] == 8 && value.data()[9] == 8 && value.data()[16] == 13);
    const uint8_t address[] = {10, 1, 0, 1};
    assert(!memcmp(value.data() + 3, address, 4) && !memcmp(value.data() + 10, address, 4) &&
           !memcmp(value.data() + 18, address, 4));
    assert(!memcmp(value.data() + 22, before.data() + 22, 4));
    assert(!memcmp(value.reply().data(), before.reply().data(), value.reply().size()));
    // A copied packet retains the pending local-hop decision.
    before.forward(0x0a010001);
    assert(before.data()[2] == 8);
    // Transit packets do not consume source-route slots without a local hop.
    assert(!value.assign(combined, sizeof(combined), 0x0a000002, 0x0a000001, 12345));
    value.forward(0x0a010001);
    const uint8_t incoming[] = {10, 0, 0, 1};
    assert(value.data()[2] == 4 && !memcmp(value.data() + 18, incoming, 4));
}

static void deferred_receive() {
    const uint8_t record[] = {7, 15, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    Options sent;
    assert(!sent.assign(record, sizeof(record)));
    uint8_t first[40]{}, reply[40]{};
    assert(sent.emit(first, sizeof(first), 0x0a000002, 0x0a010001, 1000) == 16);
    ax::ip4::ReceivedOptions received;
    assert(!received.assign(first, 16, 0x0a000001, 0x0a000001, 2000));
    assert(first[2] == 8 && received.data()[2] == 12);
    const uint8_t address[] = {10, 0, 0, 1};
    assert(!memcmp(received.data() + 7, address, 4));
    assert(received.reply().emit(reply, sizeof(reply), 0x0a000001, 0x0a000001, 2000) == 16);
    const uint8_t recorded[] = {7, 15, 16, 10, 1, 0, 1, 10, 0, 0, 1, 10, 0, 0, 1, 0};
    assert(!memcmp(reply, recorded, sizeof(recorded)));
    const uint8_t time[] = {68, 20, 5, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    assert(!sent.assign(time, sizeof(time)));
    assert(sent.emit(first, sizeof(first), 0x0a000002, 0x0a010001, 1000) == 20);
    assert(!received.assign(first, 20, 0x0a000001, 0x0a000001, 2000));
    assert(first[2] == 13 && received.data()[2] == 21);
    assert(received.reply().emit(reply, sizeof(reply), 0x0a000001, 0x0a000001, 3000) == 20);
    const uint8_t timed[] = {68, 20, 21, 1, 10, 1, 0, 1, 0, 0, 3, 232, 10, 0, 0, 1, 0, 0, 7, 208};
    assert(!memcmp(reply, timed, sizeof(timed)));
}

int main(int argc, char** argv) {
    received_routes();
    deferred_receive();
    source_route_permissions();
    if (argc == 2 && std::string(argv[1]) == "receive")
        return receive_rules();
    assert(argc == 1);
    std::string name, input, expected_output;
    unsigned raw;
    int expected_result;
    size_t observations = 0;
    while (std::cin >> name >> raw >> input >> expected_result >> expected_output) {
        auto bytes = decode(input), expected = decode(expected_output);
        const uint8_t seed[]{1, 1, 1, 1};
        Options value;
        assert(!value.assign(seed, sizeof(seed)));
        int result = value.assign(bytes.data(), bytes.size(), {raw != 0});
        if (result != expected_result || value.size() != expected.size() ||
            (!expected.empty() && memcmp(value.data(), expected.data(), expected.size()))) {
            std::cerr << "native option mismatch: " << name << " raw=" << raw
                      << " result=" << result << " expected=" << expected_result
                      << " length=" << value.size() << " expected_length=" << expected.size()
                      << '\n';
            return 1;
        }
        observations++;
    }
    assert(std::cin.eof() && observations == 14220);
    output_rules();
    failure_ownership();
    Options empty;
    assert(!empty.assigned() && empty.size() == 0);
    assert(empty.assign(nullptr, 0) == 0 && empty.assigned() && empty.size() == 0);
    auto retained = empty;
    assert(retained.assigned() && retained.emit(nullptr, 0, 0, 0, 0) == 0);
    const uint8_t invalid[] = {7, 2, 0};
    assert(retained.assign(invalid, sizeof(invalid)) == -22 && retained.assigned() &&
           retained.size() == 0);
    std::cout << "IPV4_OPTIONS_HOST_PASS native_observations=" << observations
              << " mutation_cases=20000\n";
}
