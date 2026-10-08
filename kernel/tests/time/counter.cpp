// SPDX-License-Identifier: GPL-3.0-or-later
#include "core/time.hpp"
#include "firmware/acpi.hpp"
#include <array>
#include <cassert>
#include <cstdio>
#include <cstring>

using ax::Clock::Counter;

static uint64_t random_state = 0x4158363454494d45ull;

static uint64_t random_value() {
    random_state ^= random_state << 13;
    random_state ^= random_state >> 7;
    random_state ^= random_state << 17;
    return random_state;
}

static void counter_tests() {
    Counter unset;
    assert(unset.sample(100) == 0 && !unset.reset(0, 0, 1));
    Counter fraction;
    assert(fraction.reset(100, 3, 7));
    assert(fraction.sample(101) == 0 && fraction.sample(102) == 0);
    assert(fraction.sample(103) == 1 && fraction.sample(107) == 3);
    assert(fraction.sample(106) == 3 && fraction.sample(107) == 3);
    assert(fraction.sample(114) == 6);
    for (auto scale : std::array<std::array<uint64_t, 2>, 6>{{{0, 1},
                                                              {1, 0},
                                                              {2, 1},
                                                              {100000001, 100000001},
                                                              {1, 10000000000001ull},
                                                              {UINT64_MAX, UINT64_MAX}}}) {
        assert(fraction.reset(100, 3, 7) && fraction.sample(114) == 6);
        assert(!fraction.reset(0, scale[0], scale[1]));
        assert(fraction.sample(121) == 9);
    }
    Counter wrap;
    assert(wrap.reset(UINT64_MAX - 4, 1, 1));
    assert(wrap.sample(3) == 8 && wrap.sample(2) == 8 && wrap.sample(5) == 10);
    Counter saturate;
    assert(saturate.reset(0, 1, 1));
    assert(saturate.sample(INT64_MAX) == uint64_t(INT64_MAX));
    assert(saturate.sample(UINT64_MAX - 1) == UINT64_MAX - 1);
    assert(saturate.sample(1) == UINT64_MAX && saturate.sample(2) == UINT64_MAX);
    Counter ambiguous;
    assert(ambiguous.reset(0, 1, 1));
    assert(ambiguous.sample(uint64_t(INT64_MAX) + 1) == 0);
    assert(ambiguous.sample(5) == 5);

    for (unsigned fixture = 0; fixture < 4096; fixture++) {
        uint64_t numerator = 1 + random_value() % 100000000;
        uint64_t denominator = numerator + random_value() % (10000000000000ull - numerator + 1);
        uint64_t reading = random_value(), expected = 0, carry = 0;
        Counter counter;
        assert(counter.reset(reading, numerator, denominator));
        for (unsigned step = 0; step < 12; step++) {
            uint64_t delta = random_value() & uint64_t(INT64_MAX);
            reading += delta;
            unsigned __int128 scaled = static_cast<unsigned __int128>(delta) * numerator + carry;
            uint64_t whole = scaled / denominator;
            carry = scaled % denominator;
            expected = whole > UINT64_MAX - expected ? UINT64_MAX : expected + whole;
            assert(counter.sample(reading) == expected);
            assert(counter.sample(reading - 1) == expected);
        }
    }
    std::puts("CLOCK_COUNTER_PASS fixtures=4096 samples=49152 fractions_wrap_backwards_saturation");
}

struct Firmware {
    static constexpr uint64_t base = 0x100000, rsdt = base + 4096, xsdt = base + 8192,
                              hpet = base + 12288;
    std::array<uint8_t, 16384> bytes{};
    size_t readable = bytes.size(), calls = 0;

    uint8_t* at(uint64_t address) {
        return bytes.data() + address - base;
    }

    void put(uint64_t address, uint64_t value, size_t count) {
        for (size_t i = 0; i < count; i++)
            at(address)[i] = uint8_t(value >> (i * 8));
    }

    void sum(uint64_t address, size_t length, size_t field) {
        auto data = at(address);
        data[field] = 0;
        uint8_t checksum = 0;
        for (size_t i = 0; i < length; i++)
            checksum += data[i];
        data[field] = uint8_t(0 - checksum);
    }

    void rsdp_sum() {
        sum(base, 20, 8);
        sum(base, 36, 32);
    }

    Firmware() {
        std::memcpy(at(base), "RSD PTR ", 8);
        at(base)[15] = 2;
        put(base + 20, 36, 4);
        put(base + 24, xsdt, 8);
        rsdp_sum();
        std::memcpy(at(rsdt), "RSDT", 4);
        put(rsdt + 4, 40, 4);
        put(rsdt + 36, hpet, 4);
        sum(rsdt, 40, 9);
        std::memcpy(at(xsdt), "XSDT", 4);
        put(xsdt + 4, 44, 4);
        put(xsdt + 36, hpet, 8);
        sum(xsdt, 44, 9);
        std::memcpy(at(hpet), "HPET", 4);
        put(hpet + 4, 56, 4);
        put(hpet + 36, 0x8086a201, 4);
        at(hpet)[41] = 64;
        put(hpet + 44, 0xfed00000, 8);
        sum(hpet, 56, 9);
    }

    static const uint8_t* read(uint64_t address, size_t length, void* context) {
        auto& f = *static_cast<Firmware*>(context);
        f.calls++;
        if (address < base || address - base > f.readable || length > f.readable - (address - base))
            return nullptr;
        return f.at(address);
    }

    bool find(ax::Acpi::Hpet& output, uint64_t address = base) {
        calls = 0;
        bool result = ax::Acpi::find_hpet(address, read, this, output);
        assert(calls <= 1040);
        return result;
    }
};

static void firmware_tests() {
    for (unsigned variant = 0; variant < 5; variant++) {
        Firmware f;
        if (variant == 1) {
            f.at(Firmware::base)[15] = 0;
            f.put(Firmware::base + 16, Firmware::rsdt, 4);
            f.rsdp_sum();
        } else if (variant == 2) {
            f.put(Firmware::base + 16, Firmware::rsdt, 4);
            f.rsdp_sum();
            f.at(Firmware::xsdt)[9]++;
        } else if (variant == 3) {
            f.at(Firmware::hpet)[41] = 0;
            f.at(Firmware::hpet)[43] = 4;
            f.sum(Firmware::hpet, 56, 9);
        } else if (variant == 4) {
            f.put(Firmware::hpet + 44, (1ull << 52) - 1024, 8);
            f.sum(Firmware::hpet, 56, 9);
        }
        ax::Acpi::Hpet found;
        assert(f.find(found));
        assert(found.address == (variant == 4 ? (1ull << 52) - 1024 : 0xfed00000));
        assert(found.id == 0x8086a201);
    }
    constexpr unsigned malformed = 29;
    for (unsigned variant = 0; variant < malformed; variant++) {
        Firmware f;
        uint64_t address = Firmware::base;
        switch (variant) {
        case 0:
            address = 0;
            break;
        case 1:
            address = 1ull << 52;
            break;
        case 2:
            f.at(address)[0] = 'X';
            break;
        case 3:
            f.at(address)[8]++;
            break;
        case 4:
            f.at(address)[15] = 1;
            f.rsdp_sum();
            break;
        case 5:
            f.at(address)[32]++;
            break;
        case 6:
            f.put(address + 20, 35, 4);
            f.rsdp_sum();
            break;
        case 7:
            f.put(address + 20, 4097, 4);
            f.rsdp_sum();
            break;
        case 8:
            f.readable = 19;
            break;
        case 9:
            f.readable = 35;
            break;
        case 10:
            f.put(address + 24, UINT64_MAX, 8);
            f.rsdp_sum();
            break;
        case 11:
            f.put(Firmware::xsdt + 4, 35, 4);
            break;
        case 12:
            f.put(Firmware::xsdt + 4, 65537, 4);
            break;
        case 13:
            f.put(Firmware::xsdt + 4, 37, 4);
            f.sum(Firmware::xsdt, 37, 9);
            break;
        case 14:
            f.at(Firmware::xsdt)[0] = 'Z';
            f.sum(Firmware::xsdt, 44, 9);
            break;
        case 15:
            f.at(Firmware::xsdt)[9]++;
            break;
        case 16:
            f.put(Firmware::xsdt + 4, 36 + 257 * 8, 4);
            f.sum(Firmware::xsdt, 36 + 257 * 8, 9);
            break;
        case 17:
            f.put(Firmware::xsdt + 36, UINT64_MAX, 8);
            f.sum(Firmware::xsdt, 44, 9);
            break;
        case 18:
            f.at(Firmware::hpet)[0] = 'Z';
            f.sum(Firmware::hpet, 56, 9);
            break;
        case 19:
            f.at(Firmware::hpet)[9]++;
            break;
        case 20:
            f.put(Firmware::hpet + 4, 55, 4);
            break;
        case 21:
            f.put(Firmware::hpet + 4, 65537, 4);
            break;
        case 22:
            f.at(Firmware::hpet)[40] = 1;
            f.sum(Firmware::hpet, 56, 9);
            break;
        case 23:
            f.at(Firmware::hpet)[41] = 32;
            f.sum(Firmware::hpet, 56, 9);
            break;
        case 24:
            f.at(Firmware::hpet)[42] = 1;
            f.sum(Firmware::hpet, 56, 9);
            break;
        case 25:
            f.at(Firmware::hpet)[43] = 1;
            f.sum(Firmware::hpet, 56, 9);
            break;
        case 26:
            f.put(Firmware::hpet + 44, 0, 8);
            f.sum(Firmware::hpet, 56, 9);
            break;
        case 27:
            f.put(Firmware::hpet + 44, 0xfed00001, 8);
            f.sum(Firmware::hpet, 56, 9);
            break;
        case 28:
            f.put(Firmware::hpet + 44, 1ull << 52, 8);
            f.sum(Firmware::hpet, 56, 9);
            break;
        }
        ax::Acpi::Hpet found{123, 456};
        assert(!f.find(found, address) && found.address == 123 && found.id == 456);
    }
    ax::Acpi::Hpet unused;
    assert(!ax::Acpi::find_hpet(Firmware::base, nullptr, nullptr, unused));
    for (unsigned mutation = 0; mutation < 16000; mutation++) {
        Firmware f;
        size_t offset = random_value() % f.bytes.size();
        f.bytes[offset] ^= uint8_t(1 + random_value() % 255);
        ax::Acpi::Hpet output{123, 456};
        if (f.find(output))
            assert(output.address && !(output.address & 1023) &&
                   output.address <= (1ull << 52) - 1024);
        else
            assert(output.address == 123 && output.id == 456);
    }
    std::printf("CLOCK_FIRMWARE_PASS valid=5 malformed=%u mutations=16000 bounded_reads\n",
                malformed);
}

int main() {
    counter_tests();
    firmware_tests();
    std::puts("CLOCK_CODEC_TESTS_PASS");
}
