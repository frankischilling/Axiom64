// SPDX-License-Identifier: GPL-3.0-or-later
#include "net/ipv6/configuration.hpp"
#include "net/ipv6/host.hpp"
#include "core/random.hpp"
#include "core/random/primitives.hpp"
#include "net/ipv6/router.hpp"

namespace ax::ip6 {
namespace {
struct Values {
    int32_t mode = 0, disabled = 0, accept_ra = 1, autoconf = 1;
    int32_t dad_transmits = 1, enhanced_dad = 1, solicitations = -1;
};

struct Configuration {
    Values values;
    uint8_t secret[16]{};
    bool secret_initialized = false, initialized = false;
    bool administrative = false, ready = false, pending = false;
    Address generated;
    unsigned dad_counter = 0;
    bool generated_privacy = false;
};

Configuration interfaces[max_net_devices + 1], defaults, all;

Configuration* select(unsigned index) {
    if (index == configuration_all)
        return &all;
    if (index == configuration_default)
        return &defaults;
    if (index != ipv6_loopback && !net_info(index))
        return nullptr;
    auto& state = interfaces[index - 1];
    if (!state.initialized) {
        state.values = defaults.values;
        state.initialized = true;
    }
    return &state;
}

int32_t* field(Values& values, ConfigurationKey key) {
    switch (key) {
    case ConfigurationKey::generation_mode:
        return &values.mode;
    case ConfigurationKey::disabled:
        return &values.disabled;
    case ConfigurationKey::accept_ra:
        return &values.accept_ra;
    case ConfigurationKey::autoconf:
        return &values.autoconf;
    case ConfigurationKey::dad_transmits:
        return &values.dad_transmits;
    case ConfigurationKey::enhanced_dad:
        return &values.enhanced_dad;
    case ConfigurationKey::router_solicitations:
        return &values.solicitations;
    }
    return nullptr;
}

bool physical_ready(unsigned index) {
    auto info = net_info(index);
    return info && info->live && info->administrative && info->carrier && info->mtu >= minimum_mtu;
}

void withdraw(unsigned index) {
    router_link_reset(index);
    for (unsigned position = 0; auto entry = ipv6_address(position);) {
        if (entry->index == index && index != ipv6_loopback) {
            Address address = entry->address;
            ipv6_address_remove(index, address);
        } else
            position++;
    }
    route_withdraw(index);
}

bool reserved(const Address& address) {
    bool zero = true, anycast = address.bytes[8] == 0xfd;
    for (unsigned n = 8; n < 16; n++)
        zero &= !address.bytes[n];
    for (unsigned n = 9; n < 15; n++)
        anycast &= address.bytes[n] == 0xff;
    return zero || (anycast && address.bytes[15] >= 0x80);
}

bool opaque_identifier(Address& address, const uint8_t* mac, const uint8_t* secret,
                       unsigned& counter) {
    // RFC 7217 permits a pseudorandom function over the prefix, interface and
    // private key. HMAC-BLAKE2s avoids embedding the MAC in an identifier.
    uint8_t pad[64], digest[32];
    bool accepted = false;
    for (unsigned attempt = 0; attempt < 4; attempt++) {
        memset(pad, 0x36, sizeof(pad));
        for (unsigned n = 0; n < 16; n++)
            pad[n] ^= secret[n];
        random::Blake2s inner;
        inner.update(pad, sizeof(pad));
        static constexpr char domain[] = "Axiom64 IPv6 stable address";
        inner.update(domain, sizeof(domain));
        inner.update(address.bytes, 8);
        inner.update(mac, 6);
        uint8_t count[4]{uint8_t(counter >> 24), uint8_t(counter >> 16), uint8_t(counter >> 8),
                         uint8_t(counter)};
        inner.update(count, sizeof(count));
        inner.finish(digest);
        memset(pad, 0x5c, sizeof(pad));
        for (unsigned n = 0; n < 16; n++)
            pad[n] ^= secret[n];
        random::Blake2s outer;
        outer.update(pad, sizeof(pad));
        outer.update(digest, sizeof(digest));
        outer.finish(digest);
        memcpy(address.bytes + 8, digest, 8);
        address.bytes[8] &= ~uint8_t(2);
        if (!reserved(address)) {
            accepted = true;
            break;
        }
        counter++;
    }
    random::erase(pad, sizeof(pad));
    random::erase(digest, sizeof(digest));
    return accepted;
}

void generate(unsigned index, Configuration& state) {
    if (index == ipv6_loopback || !physical_ready(index) || state.values.disabled)
        return;
    state.pending = false;
    auto mode = state.values.mode;
    if (mode == 1)
        return;
    const auto* info = net_info(index);
    Address address;
    address.bytes[0] = 0xfe;
    address.bytes[1] = 0x80;
    bool privacy = mode == 2 || mode == 3;
    if (privacy) {
        const uint8_t* secret = state.secret_initialized      ? state.secret
                                : defaults.secret_initialized ? defaults.secret
                                                              : nullptr;
        if (!secret && mode == 3) {
            if (random_read(state.secret, sizeof(state.secret))) {
                state.pending = true;
                return;
            }
            state.secret_initialized = true;
            secret = state.secret;
        }
        if (!secret)
            return;
        if (!opaque_identifier(address, info->mac, secret, state.dad_counter))
            return;
    } else {
        memcpy(address.bytes + 8, info->mac, 3);
        address.bytes[8] ^= 2;
        address.bytes[11] = 0xff;
        address.bytes[12] = 0xfe;
        memcpy(address.bytes + 13, info->mac + 3, 3);
    }
    // An unchanged write or a normal poll must not resurrect an address that
    // userspace explicitly removed. Only an initialization event reaches here.
    int error = ipv6_address_add({address, index, uint16_t(privacy ? 0x880 : 0x80), 64});
    if (error && error != -17)
        state.pending = true;
    else if (!error) {
        state.generated = address;
        state.generated_privacy = privacy;
    }
}

int validate(unsigned index, Configuration& state, ConfigurationKey key, int32_t value) {
    if (!field(state.values, key))
        return -22;
    if (key == ConfigurationKey::generation_mode) {
        if (value < 0 || value > 3)
            return -22;
        if (value == 2 && index != configuration_all && index != configuration_default &&
            !state.secret_initialized && !defaults.secret_initialized)
            return -22;
    }
    if (key == ConfigurationKey::router_solicitations && value < -1)
        return -22;
    return 0;
}

void assign(unsigned index, Configuration& state, ConfigurationKey key, int32_t value,
            ConfigurationWrite source) {
    auto& selected = *field(state.values, key);
    bool changed = selected != value;
    selected = value;
    if (index == configuration_all || index == configuration_default)
        return;
    if (key == ConfigurationKey::disabled && changed) {
        state.pending = false;
        if (value)
            withdraw(index);
        else
            generate(index, state);
    }
    if (key == ConfigurationKey::generation_mode && changed && source == ConfigurationWrite::sysctl)
        generate(index, state);
}
} // namespace

int configuration_read(unsigned index, ConfigurationKey key, int32_t& value) {
    auto state = select(index);
    if (!state)
        return -19;
    auto selected = field(state->values, key);
    if (!selected)
        return -22;
    value = *selected;
    return 0;
}

int configuration_identifier(unsigned index, Address& address, unsigned& counter, bool& privacy) {
    auto state = select(index);
    auto info = net_info(index);
    if (!state || !info)
        return -19;
    privacy = state->values.mode == 2 || state->values.mode == 3;
    if (privacy) {
        const uint8_t* secret = state->secret_initialized     ? state->secret
                                : defaults.secret_initialized ? defaults.secret
                                                              : nullptr;
        if (!secret && state->values.mode == 3) {
            int error = random_read(state->secret, sizeof(state->secret));
            if (error)
                return error;
            state->secret_initialized = true;
            secret = state->secret;
        }
        if (!secret)
            return -22;
        return opaque_identifier(address, info->mac, secret, counter) ? 0 : -99;
    }
    memcpy(address.bytes + 8, info->mac, 3);
    address.bytes[8] ^= 2;
    address.bytes[11] = 0xff;
    address.bytes[12] = 0xfe;
    memcpy(address.bytes + 13, info->mac + 3, 3);
    return 0;
}

int configuration_write(unsigned index, ConfigurationKey key, int32_t value,
                        ConfigurationWrite source) {
    auto state = select(index);
    if (!state)
        return -19;
    int error = validate(index, *state, key, value);
    if (error)
        return error;
    if (source == ConfigurationWrite::netlink &&
        (key != ConfigurationKey::generation_mode || index == configuration_all ||
         index == configuration_default))
        return -22;
    assign(index, *state, key, value, source);
    if (index == configuration_all &&
        (key == ConfigurationKey::generation_mode || key == ConfigurationKey::disabled)) {
        assign(configuration_default, defaults, key, value, source);
        for (unsigned at = 1; at <= ipv6_loopback; at++)
            if (auto current = select(at))
                assign(at, *current, key, value, source);
    }
    return 0;
}

int configuration_secret(unsigned index, const Address& secret) {
    if (index == configuration_all)
        return -5;
    auto state = select(index);
    if (!state)
        return -19;
    random::erase(state->secret, sizeof(state->secret));
    memcpy(state->secret, secret.bytes, sizeof(state->secret));
    state->secret_initialized = true;
    state->dad_counter = 0;
    // Installing a key selects privacy mode without generating an address.
    // A default key changes existing interfaces, not the default mode itself.
    if (index == configuration_default) {
        for (unsigned at = 1; at <= ipv6_loopback; at++)
            if (auto current = select(at))
                current->values.mode = 2;
    } else
        state->values.mode = 2;
    return 0;
}

int configuration_secret_read(unsigned index, Address& secret) {
    if (index == configuration_all)
        return -5;
    auto state = select(index);
    if (!state)
        return -19;
    if (!state->secret_initialized)
        return -5;
    memcpy(secret.bytes, state->secret, sizeof(state->secret));
    return 0;
}

bool configuration_disabled(unsigned index) {
    auto state = select(index);
    return !state || state->values.disabled;
}

void configuration_registered(unsigned index) {
    auto state = select(index);
    if (!state)
        return;
    random::erase(state, sizeof(*state));
    state->values = defaults.values;
    state->initialized = true;
    configuration_changed(index);
}

void configuration_changed(unsigned index) {
    auto state = select(index);
    auto info = net_info(index);
    if (!state || !info)
        return;
    bool ready = physical_ready(index);
    if ((state->administrative && !info->administrative) ||
        (state->ready && info->mtu < minimum_mtu)) {
        withdraw(index);
        state->pending = false;
    }
    bool initialize = ready && !state->ready;
    state->administrative = info->administrative;
    state->ready = ready;
    if (initialize)
        generate(index, *state);
}

void configuration_address_removed(unsigned index, const Address& address) {
    auto state = select(index);
    if (state && state->generated == address) {
        state->generated = {};
        state->generated_privacy = false;
    }
}

void configuration_poll() {
    for (unsigned index = 1; index <= max_net_devices; index++) {
        if (!net_info(index))
            continue;
        configuration_changed(index);
        auto state = select(index);
        if (state && state->generated_privacy && state->values.mode >= 2) {
            for (unsigned position = 0; auto entry = ipv6_address(position); position++) {
                if (entry->index != index || !(entry->address == state->generated) ||
                    !(entry->flags & 8))
                    continue;
                state->generated_privacy = false;
                if (state->dad_counter < 3) {
                    auto duplicate = entry->address;
                    ipv6_address_remove(index, duplicate);
                    state->dad_counter++;
                    state->pending = true;
                }
                break;
            }
        }
        if (state && state->pending)
            generate(index, *state);
    }
}

void configuration_reset() {
    random::erase(interfaces, sizeof(interfaces));
    random::erase(&defaults, sizeof(defaults));
    random::erase(&all, sizeof(all));
    defaults = {};
    all = {};
}
} // namespace ax::ip6
