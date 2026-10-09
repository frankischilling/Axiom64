// SPDX-License-Identifier: GPL-3.0-or-later
#include "core/random/engine.hpp"
#include <assert.h>
#include <stdio.h>
#include <string.h>

using ax::random::Blake2s;
using ax::random::Generator;
using ax::random::SeedSource;

static void expected(const uint8_t* bytes, size_t size, const char* hex) {
    assert(strlen(hex) == size * 2);
    for (size_t i = 0; i < size; i++) {
        unsigned value;
        assert(sscanf(hex + 2 * i, "%2x", &value) == 1);
        if (bytes[i] != value)
            fprintf(stderr, "RANDOM_VECTOR_FAIL prefix=%.8s offset=%zu actual=%02x expected=%02x\n",
                    hex, i, unsigned(bytes[i]), value);
        assert(bytes[i] == value);
    }
}

static void primitives() {
    uint8_t key[32], nonce[12] = {0, 0, 0, 9, 0, 0, 0, 0x4a}, block[64];
    for (unsigned i = 0; i < sizeof(key); i++)
        key[i] = i;
    ax::random::chacha20_block(block, key, 1, nonce);
    expected(block, 64,
             "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e"
             "d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e");
    memset(key, 0, sizeof(key));
    memset(nonce, 0, sizeof(nonce));
    ax::random::chacha20_block(block, key, 0, nonce);
    expected(block, 64,
             "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7"
             "da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586");
    Blake2s abc;
    abc.update("abc", 3);
    abc.finish(key);
    expected(key, 32, "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982");
    for (size_t i = 0; i < sizeof(abc); i++)
        assert(reinterpret_cast<const uint8_t*>(&abc)[i] == 0);

    // Independent Python hashlib BLAKE2s vectors; exercise final full blocks and every split.
    struct Vector {
        size_t size;
        const char* digest;
    };

    const Vector vectors[] = {
        {0, "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9"},
        {1, "e34d74dbaf4ff4c6abd871cc220451d2ea2648846c7757fbaac82fe51ad64bea"},
        {63, "e57cb79487dd57902432b250733813bd96a84efce59f650fac26e6696aefafc3"},
        {64, "56f34e8b96557e90c1f24b52d0c89d51086acf1b00f634cf1dde9233b8eaaa3e"},
        {65, "1b53ee94aaf34e4b159d48de352c7f0661d0a40edff95a0b1639b4090e974472"},
        {127, "f18417b39d617ab1c18fdf91ebd0fc6d5516bb34cf39364037bce81fa04cecb1"},
        {128, "1fa877de67259d19863a2a34bcc6962a2b25fcbf5cbecd7ede8f1fa36688a796"},
        {129, "5bd169e67c82c2c2e98ef7008bdf261f2ddf30b1c00f9e7f275bb3e8a28dc9a2"},
        {255, "f03f5789d3336b80d002d59fdf918bdb775b00956ed5528e86aa994acb38fe2d"},
        {256, "5fdeb59f681d975f52c8e69c5502e02a12a3afcc5836ba58f42784c439228781"},
        {1024, "a049455add68f38d48845e25a52ba3100c4d0899178c202aec07364fecacf650"}};
    uint8_t input[1024];
    for (unsigned i = 0; i < sizeof(input); i++)
        input[i] = i;
    for (const auto& vector : vectors)
        for (size_t split = 0; split <= vector.size; split++) {
            Blake2s hash;
            hash.update(input, split);
            hash.update(input + split, vector.size - split);
            hash.update(nullptr, 0);
            hash.finish(key);
            expected(key, 32, vector.digest);
        }
    puts("RANDOM_PRIMITIVES_PASS chacha=2 blake2s=12 splits=all erase=checked");
}

static void generator() {
    Generator unready;
    uint8_t seed[32], output[96], reference[96];
    for (unsigned i = 0; i < sizeof(seed); i++)
        seed[i] = i;
    memset(output, 0xa5, sizeof(output));
    assert(!unready.ready() && unready.read(output, sizeof(output)) == -11);
    for (auto byte : output)
        assert(byte == 0xa5);
    unready.mix(seed, sizeof(seed));
    assert(!unready.ready() && unready.read(output, 1) == -11);
    assert(unready.read(output, sizeof(output), true) == 0 && !unready.ready());

    Generator seeded, twin;
    seeded.seed(seed);
    twin.seed(seed);
    assert(seeded.ready() && seeded.read(output, sizeof(output)) == 0);
    // Independent hashlib + cryptography ChaCha20 construction, not this implementation.
    expected(output, sizeof(output),
             "f5a1fe609bcb3c44d2e75595dd3a7ba8351406144e6647689c55dc4245a2c19b8"
             "3fce56530f4d94e6ce894a04672dc0a0fb870f75f3a214b9a5da3fc16bd80624"
             "82eb75ee907806181c9fe9b44965da91c143b21e94f6e9dab4cf0e688405336");
    assert(twin.read(reference, 32) == 0 && twin.read(reference + 32, 64) == 0);
    assert(!memcmp(output, reference, sizeof(output)));
    assert(seeded.read(output, sizeof(output)) == 0 && memcmp(output, reference, sizeof(output)));
    twin.mix("uncredited", 10);
    assert(twin.ready() && twin.read(reference, sizeof(reference)) == 0);
    assert(memcmp(output, reference, sizeof(output)));
    seeded.seed(seed);
    assert(seeded.ready() && seeded.read(output, sizeof(output)) == 0);
    assert(memcmp(output, reference, sizeof(output)));
    Generator partial, whole;
    partial.seed(seed);
    whole.seed(seed);
    assert(partial.read(output, 1) == 0 && partial.read(output + 1, 32) == 0);
    assert(whole.read(reference, 64) == 0);
    assert(output[0] == reference[0] && !memcmp(output + 1, reference + 32, 32));
    puts(
        "RANDOM_GENERATOR_PASS unready=checked insecure=uncredited rekey=independent pool=checked");
}

struct Hardware {
    uint64_t words[4] = {0x0123456789abcdef, 0xfedcba9876543210, 0x1701280017022800,
                         0x4158494f4d363431};
    unsigned calls = 0, supplied = 0, failures = 0, stop_after = UINT32_MAX;
    bool always_fail = false, last_attempt = false;

    static bool read(void* context, uint64_t& word) {
        auto& fixture = *static_cast<Hardware*>(context);
        fixture.calls++;
        word = 0x1234; // A clear carry flag makes even a nonzero destination unusable.
        if (fixture.always_fail || fixture.supplied == fixture.stop_after ||
            fixture.calls <= fixture.failures || (fixture.last_attempt && fixture.calls % 10))
            return false;
        word = fixture.words[fixture.supplied++ % 4];
        return true;
    }
};

static void sources() {
    Hardware unavailable;
    Generator policy;
    SeedSource denied(false, Hardware::read, &unavailable);
    assert(!denied.seed(policy) && !policy.ready() && !unavailable.calls);
    Hardware failed;
    failed.always_fail = true;
    SeedSource carry(true, Hardware::read, &failed);
    assert(!carry.seed(policy) && !policy.ready() && failed.calls == 10);
    Hardware partial;
    partial.stop_after = 2;
    Generator unchanged, reference;
    uint8_t initial[32]{}, actual[32], wanted[32];
    unchanged.seed(initial);
    reference.seed(initial);
    SeedSource incomplete(true, Hardware::read, &partial);
    assert(!incomplete.seed(unchanged) && partial.calls == 12 && unchanged.ready());
    assert(unchanged.read(actual, sizeof(actual)) == 0 &&
           reference.read(wanted, sizeof(wanted)) == 0 && !memcmp(actual, wanted, sizeof(actual)));
    const uint64_t invalid_words[] = {0, UINT64_MAX, 0x123456};
    for (uint64_t invalid : invalid_words) {
        Hardware stuck;
        for (auto& word : stuck.words)
            word = invalid;
        SeedSource health(true, Hardware::read, &stuck);
        assert(!health.seed(policy) && !policy.ready() && stuck.calls <= 2);
    }
    Hardware retries;
    retries.last_attempt = true;
    SeedSource bounded(true, Hardware::read, &retries);
    assert(bounded.seed(policy) && policy.ready() && retries.calls == 40);
    uint8_t before[32], after[32];
    assert(policy.read(before, sizeof(before)) == 0);
    // Repetition of the previous completed seed is rejected, even after initialization.
    assert(!bounded.seed(policy) && policy.ready() && retries.calls == 80);
    for (auto& word : retries.words)
        word += 100;
    assert(bounded.seed(policy) && policy.ready() && retries.calls == 120);
    assert(policy.read(after, sizeof(after)) == 0 && memcmp(before, after, sizeof(before)));
    puts("RANDOM_SOURCE_PASS absent=checked carry=checked stuck=checked retries=40 reseed=checked");
}

int main() {
    primitives();
    generator();
    sources();
    puts("RANDOM_NATIVE_PASS");
}
