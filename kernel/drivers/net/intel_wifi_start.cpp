// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/drivers/net/intel_wifi_start.cpp
 * @brief   Start AX201 QuZ firmware, receive ALIVE, and stop DMA.
 * @author  frankischilling
 * @date    2026-11-23
 *
 * The Gen2 sequence follows Linux iwlwifi pcie/trans.c, pcie/trans-gen2.c,
 * pcie/rx.c, iwl-csr.h, and iwl-prph.h. API 77 advertises ALIVE version 6.
 *
 * Copyright (C) 2026 frankischilling
 */
#include "drivers/net/intel_wifi_live.hpp"
#include "drivers/net/intel_wifi_channel.hpp"
#include "drivers/net/intel_wifi_key.hpp"
#include "mm/dma.hpp"

namespace ax::IntelWifi {
namespace {
constexpr unsigned hw_if = 0x00, interrupts = 0x08, interrupt_mask = 0x0c, flow_interrupts = 0x10;
constexpr unsigned reset = 0x20, gp = 0x24, gio = 0x3c, context_base = 0x40, driver_gp_clear = 0x5c;
constexpr unsigned mailbox_set = 0x88, shadow_control = 0xa8, gio_chicken = 0x100;
constexpr unsigned hpet_debug = 0x240, link_power = 0x250;
constexpr unsigned prph_write_address = 0x444, prph_read_address = 0x448;
constexpr unsigned prph_write_data = 0x44c, prph_read_data = 0x450;
constexpr unsigned command_write_pointer = 0x460;
constexpr unsigned hpm_debug = 0xa03440, hpm_power = 0xa03458, hpm_ltr_control = 0xa0348c;
constexpr unsigned hpm_ltr = 0xa03480, peripheral_write_protect = 0xa04d00, cpu_start = 0xa05c44;
constexpr uint32_t pci_owned = 1u << 22, wake_me = 1u << 27, hap_wake = 1u << 19;
constexpr uint32_t init_done = 1u << 2, access_request = 1u << 3, clock_ready = 1u << 0;
constexpr uint32_t sleeping = 1u << 4, rf_enabled = 1u << 27, software_reset = 1u << 7;
constexpr uint32_t stop_master = 1u << 9, master_disabled = 1u << 8;
constexpr uint32_t alive_interrupt = 1u, rx_interrupt = 1u << 31;
constexpr uint32_t error_interrupts = (1u << 29) | (1u << 25);

struct Registers {
    const FirmwareBootIo& io;

    uint32_t read(unsigned offset) const {
        return io.read(io.context, offset);
    }

    void write(unsigned offset, uint32_t value) const {
        io.write(io.context, offset, value);
    }

    bool delay(unsigned microseconds) const {
        return io.delay(io.context, microseconds);
    }

    bool update(unsigned offset, uint32_t set, uint32_t clear = 0) const {
        const auto value = read(offset);
        if (value == UINT32_MAX)
            return false;
        write(offset, (value & ~clear) | set);
        return true;
    }

    bool wait(unsigned offset, uint32_t mask, uint32_t value, unsigned attempts) const {
        for (unsigned i = 0; i < attempts; ++i) {
            const auto current = read(offset);
            if (current == UINT32_MAX)
                return false;
            if ((current & mask) == value)
                return true;
            if (!delay(10))
                return false;
        }
        return false;
    }

    uint32_t read_peripheral(unsigned address) const {
        write(prph_read_address, 0x03000000 | address);
        return read(prph_read_data);
    }

    void write_peripheral(unsigned address, uint32_t value) const {
        write(prph_write_address, 0x03000000 | address);
        write(prph_write_data, value);
    }
};

bool claim(const Registers& reg) {
    if (!reg.update(hw_if, pci_owned) || !reg.wait(hw_if, pci_owned, pci_owned, 5))
        return false;
    return reg.update(mailbox_set, 1u << 5);
}

bool claim_with_wake(const Registers& reg) {
    if (claim(reg))
        return true;
    const auto power = reg.read(link_power);
    if (power == UINT32_MAX)
        return false;
    reg.write(link_power, power | (1u << 31));
    if (!reg.delay(1000) || !reg.update(hw_if, wake_me)) {
        reg.write(link_power, power);
        return false;
    }
    bool owned = false;
    for (unsigned i = 0; i < 150 && !owned; ++i) {
        owned = claim(reg);
        if (!owned && !reg.delay(1000))
            break;
    }
    reg.write(link_power, power);
    return owned;
}

bool acquire_mac(const Registers& reg) {
    return reg.update(gp, init_done | access_request) && reg.delay(2) &&
           reg.wait(gp, clock_ready | sleeping, clock_ready, 2500);
}

bool reset_adapter(const Registers& reg) {
    if (!reg.update(reset, software_reset))
        return false;
    for (unsigned i = 0; i < 5; ++i)
        if (!reg.delay(1000))
            return false;
    return true;
}

const char* prepare_adapter(const Registers& reg, bool& owned) {
    if (!acquire_mac(reg))
        return "MAC clock did not start";
    const auto debug = reg.read_peripheral(hpm_debug);
    constexpr uint32_t persistence = 1u << 12;
    if (debug != UINT32_MAX && (debug & 0xfffffff0u) != 0xa5a5a5a0 && (debug & persistence)) {
        const auto protection = reg.read_peripheral(peripheral_write_protect);
        if (protection & persistence)
            return "firmware persistence is write-protected";
        reg.write_peripheral(hpm_debug, debug & ~persistence);
    }
    owned = reset_adapter(reg) && claim_with_wake(reg);
    if (!owned || !acquire_mac(reg))
        return "MAC did not return after reset";

    // The integrated 22000 MAC needs the power-gating sequence before the final reset.
    const auto power = reg.read_peripheral(hpm_power);
    if (power == UINT32_MAX || (power & 0xfffffff0u) == 0xa5a5a5a0)
        return "MAC power registers unavailable";
    constexpr uint32_t force_active = 1u << 10, enable_gating_and_sleep = 3;
    reg.write_peripheral(hpm_power, power | force_active);
    if (!reg.delay(20))
        return "MAC power wait failed";
    reg.write_peripheral(hpm_power, power | force_active | enable_gating_and_sleep);
    if (!reg.delay(20))
        return "MAC power wait failed";
    reg.write_peripheral(hpm_power, (power | enable_gating_and_sleep) & ~force_active);

    owned = reset_adapter(reg) && claim_with_wake(reg);
    if (!owned)
        return "MAC did not return after power setup";
    reg.write(interrupt_mask, 0);
    reg.write(interrupts, UINT32_MAX);
    reg.write(flow_interrupts, UINT32_MAX);
    if (!reg.update(gio_chicken, 1u << 23) || !reg.update(hpet_debug, 0xffff0000) ||
        !reg.update(hw_if, hap_wake) || !reg.update(gio, 2) || !acquire_mac(reg))
        return "MAC clock did not stabilize";
    const auto control = reg.read(gp);
    if (control == UINT32_MAX)
        return "MAC registers unavailable";
    if (!(control & rf_enabled))
        return "Wi-Fi is blocked by the hardware switch";
    reg.write(driver_gp_clear, (1u << 1) | (1u << 2));
    reg.write(shadow_control, 0x800fffff);
    // Keep the integrated MAC's ROM reads within the PCIe latency budget during boot.
    constexpr uint32_t ltr_250us = 0x80008000 | (2u << 26) | (250u << 16) | (2u << 10) | 250u;
    reg.write_peripheral(hpm_ltr_control, 0xf);
    reg.write_peripheral(hpm_ltr, ltr_250us);
    return nullptr;
}

AlivePacket decode_alive(const FirmwarePacket& packet) {
    if (packet.opcode != 1 || packet.group != 0)
        return AlivePacket::missing;
    if (packet.length < 144)
        return AlivePacket::malformed;
    return packet.payload[0] == 0xfe && packet.payload[1] == 0xca ? AlivePacket::success
                                                                  : AlivePacket::rejected;
}

const char* wait_for_alive(const Registers& reg, ReceiveReader& rx) {
    bool posted = false;
    for (unsigned i = 0; i < 2000; ++i) {
        const auto cause = reg.read(interrupts);
        if (cause == UINT32_MAX || (cause & error_interrupts))
            return "firmware startup hardware error";
        if (!posted && (cause & alive_interrupt)) {
            // Firmware programs the RX engine before it raises ALIVE. Publish whole blocks of
            // eight.
            rx.post_initial();
            posted = true;
        }
        if (cause)
            reg.write(interrupts, cause);
        if (posted) {
            FirmwarePacket packet{};
            PacketRead received;
            while ((received = rx.next(packet)) == PacketRead::packet) {
                const auto alive = decode_alive(packet);
                if (alive == AlivePacket::success)
                    return nullptr;
                if (alive == AlivePacket::rejected)
                    return "firmware rejected startup";
                if (alive == AlivePacket::malformed)
                    return "invalid firmware notification";
            }
            if (received == PacketRead::malformed)
                return "invalid firmware notification";
        }
        if (!reg.delay(1000))
            return "firmware startup timer unavailable";
    }
    return posted ? "firmware ALIVE message timed out" : "firmware ALIVE interrupt timed out";
}

enum class Reply { matched, rejected, broken, timeout };
enum class WaitFor { reply, initialization };

struct CommandSession {
    const Registers& reg;
    ReceiveReader& rx;
    uint16_t& index;
    bool init_complete = false;

    bool acknowledge_pending() const {
        const auto cause = reg.read(interrupts);
        const auto control = reg.read(gp);
        if (cause == UINT32_MAX || (cause & error_interrupts) || control == UINT32_MAX ||
            !(control & rf_enabled))
            return false;
        if (cause)
            reg.write(interrupts, cause);
        return true;
    }

    Reply wait(uint8_t group, uint8_t opcode, uint16_t sequence, FirmwarePacket& packet,
               WaitFor event = WaitFor::reply) {
        for (unsigned attempt = 0; attempt < 2000; ++attempt) {
            if (!acknowledge_pending())
                return Reply::broken;
            PacketRead received;
            while ((received = rx.next(packet)) == PacketRead::packet) {
                if (packet.group == 0 && packet.opcode == 4)
                    init_complete = true;
                if (event == WaitFor::initialization) {
                    if (init_complete)
                        return Reply::matched;
                    continue;
                }
                if (packet.sequence != sequence)
                    continue;
                if (packet.group == group && packet.opcode == opcode)
                    return Reply::matched;
                if (packet.group == 0 && packet.opcode == 2)
                    return Reply::rejected;
            }
            if (received == PacketRead::malformed || !reg.delay(1000))
                return Reply::broken;
        }
        return Reply::timeout;
    }

    bool submit(uint8_t group, uint8_t opcode, const uint8_t* payload, size_t bytes) {
        const auto& memory = rx.memory;
        const unsigned slot = index & (command_ring_entries - 1);
        if (!prepare_host_command((*memory.command_payloads)[slot],
                                  memory.command_dma + slot * command_slot_bytes,
                                  memory.commands[slot], index, group, opcode, payload, bytes))
            return false;
        __atomic_thread_fence(__ATOMIC_RELEASE);
        // The firmware doorbell and reply sequence wrap independently of the DMA slots.
        index = (index + 1) & (command_sequence_count - 1);
        reg.write(command_write_pointer, index);
        return true;
    }

    Reply send(uint8_t group, uint8_t opcode, const uint8_t* payload, size_t bytes,
               FirmwarePacket& packet) {
        const auto sequence = index;
        return submit(group, opcode, payload, bytes) ? wait(group, opcode, sequence, packet)
                                                     : Reply::broken;
    }

    void poll_scan(PassiveScanExchange& exchange, uint64_t now_ms) {
        exchange.expire(now_ms);
        if (exchange.outcome() != ScanOutcome::pending)
            return;
        if (!acknowledge_pending()) {
            exchange.receive_failed();
            return;
        }
        // Drain a bounded number of notifications before yielding to the caller.
        for (unsigned i = 0; i < 64 && exchange.outcome() == ScanOutcome::pending; ++i) {
            FirmwarePacket packet{};
            const auto received = rx.next(packet);
            if (received != PacketRead::packet) {
                if (received == PacketRead::malformed)
                    exchange.receive_failed();
                break;
            }
            exchange.observe(packet, now_ms);
        }
    }

    bool poll_idle() {
        if (!acknowledge_pending())
            return false;
        for (unsigned i = 0; i < 64; ++i) {
            FirmwarePacket packet{};
            const auto result = rx.next(packet);
            if (result != PacketRead::packet)
                return result == PacketRead::end;
        }
        return true;
    }
};

const char* request_nvm(CommandSession& commands, NvmInfo& info) {
    FirmwarePacket response{};
    const uint8_t init_config[4]{1u << 1};
    const uint8_t reserved[4]{};
    if (commands.send(2, 3, init_config, sizeof(init_config), response) != Reply::matched)
        return "firmware init configuration failed";
    if (commands.send(12, 0, reserved, sizeof(reserved), response) != Reply::matched)
        return "firmware NVM access completion failed";
    if (!commands.init_complete &&
        commands.wait(0, 4, 0, response, WaitFor::initialization) != Reply::matched)
        return "firmware initialization did not complete";
    if (commands.send(12, 2, reserved, sizeof(reserved), response) != Reply::matched)
        return "firmware NVM query failed";
    if (!read_nvm_v4(response, info))
        return "firmware returned invalid NVM data";
    return nullptr;
}

const char* configure_scan(CommandSession& commands, const NvmInfo& nvm,
                           const AntennaMasks& firmware) {
    const auto tx = uint8_t(nvm.tx_chains & firmware.tx);
    const auto rx = uint8_t(nvm.rx_chains & firmware.rx);
    if (!tx || !rx)
        return "firmware and NVM antenna masks do not overlap";
    // Reduced scan configuration v5. Upstream leaves mode and station fields zero.
    const uint8_t config[12]{0, 0, 0, 0, tx, 0, 0, 0, rx};
    FirmwarePacket response{};
    return commands.send(1, 0xc, config, sizeof(config), response) == Reply::matched
               ? nullptr
               : "firmware scan configuration failed";
}

const char* request_regulatory_profile(CommandSession& commands, const NvmInfo& nvm,
                                       RegulatoryProfile& profile) {
    if (!nvm.lar_enabled)
        return "firmware NVM has location-aware regulation disabled";
    // Query the active firmware profile using the NVM default code and GET_CURRENT source.
    const uint8_t request[28]{'Z', 'Z', 0x10};
    FirmwarePacket response{};
    if (commands.send(1, 0xc8, request, sizeof(request), response) != Reply::matched)
        return "firmware regulatory profile query failed";
    if (!read_regulatory_v5(response, profile))
        return "firmware returned an invalid regulatory profile";
    return profile.valid_channels ? nullptr
                                  : "firmware regulatory profile has no permitted channels";
}

const char* configure_tx_antennas(CommandSession& commands, const NvmInfo& nvm,
                                  const AntennaMasks& firmware) {
    FirmwarePacket reply{};
    const uint8_t tx_mask[4]{uint8_t(nvm.tx_chains & firmware.tx)};
    if (!tx_mask[0])
        return "firmware and NVM transmit antenna masks do not overlap";
    if (commands.send(1, 0x98, tx_mask, sizeof(tx_mask), reply) != Reply::matched)
        return "firmware TX antenna configuration failed";
    return nullptr;
}

const char* configure_scan_station(CommandSession& commands, uint8_t (&address)[6]) {
    // The 22000-family CSR holds optional OEM straps followed by an OTP fallback.
    const auto& reg = commands.reg;
    if (!decode_station_address(reg.read(0x388), reg.read(0x38c), address) &&
        !decode_station_address(reg.read(0x380), reg.read(0x384), address))
        return "adapter has no valid station MAC address";
    uint8_t mac[mac_context_bytes];
    prepare_scan_station(address, mac);
    FirmwarePacket reply{};
    if (commands.send(1, 0x28, mac, sizeof(mac), reply) != Reply::matched)
        return "firmware station context setup failed";
    return nullptr;
}

const char* apply_channel_context(CommandSession& commands, const ScanChannel& channel,
                                  uint8_t rx_mask, bool dual_lmac, bool attach,
                                  bool initialize_fifo = false) {
    if (!rx_mask)
        return "firmware and NVM receive antenna masks do not overlap";

    constexpr struct {
        ChannelStep step;
        bool attach;
        const char* failure;
    } steps[]{
        {ChannelStep::add_phy, true, "PHY context add failed"},
        {ChannelStep::rx_chains, true, "radio chain configuration failed"},
        {ChannelStep::initialize_fifo, true, "unassociated receive FIFO setup failed"},
        {ChannelStep::bind, true, "station channel binding failed"},
        {ChannelStep::unbind, false, "station channel unbind failed"},
        {ChannelStep::remove_phy, false, "PHY context removal failed"},
    };

    for (const auto& step : steps) {
        if (step.attach != attach ||
            (!initialize_fifo && step.step == ChannelStep::initialize_fifo))
            continue;
        const auto command = channel_command(step.step, channel, rx_mask, dual_lmac);
        FirmwarePacket reply{};
        if (commands.send(command.group, command.opcode, command.bytes, command.size, reply) !=
                Reply::matched ||
            (command.has_status && !binding_succeeded(reply)))
            return step.failure;
    }
    return nullptr;
}

const char* check_channel_contexts(CommandSession& commands, const ScanChannelList& list,
                                   uint8_t rx_mask, bool dual_lmac, unsigned& checked) {
    bool bands[2]{};
    for (unsigned i = 0; i < list.count; ++i) {
        const auto& channel = list.entries[i];
        const bool high = channel.frequency_mhz >= 5000;
        if (!channel.allowed || bands[high])
            continue;
        if (const auto* error =
                apply_channel_context(commands, channel, rx_mask, dual_lmac, true, !checked))
            return error;
        if (const auto* error = apply_channel_context(commands, channel, rx_mask, dual_lmac, false))
            return error;
        bands[high] = true;
        ++checked;
    }
    return checked ? nullptr : "no permitted 2.4 or 5 GHz channels";
}

bool send_key_command(CommandSession& commands, uint8_t (&wire)[key_command_bytes]) {
    const unsigned slot = commands.index & (command_ring_entries - 1);
    FirmwarePacket response{};
    const auto reply =
        commands.send(key_command_group, key_command_opcode, wire, sizeof(wire), response);
    erase_key_bytes(wire, sizeof(wire));
    // Matching replies return the command buffer to the host. On timeout the caller
    // stops DMA before releasing it.
    if (reply == Reply::matched || reply == Reply::rejected) {
        auto& payload = (*commands.rx.memory.command_payloads)[slot];
        erase_key_bytes(payload, sizeof(payload));
    }
    return reply == Reply::matched;
}

const char* check_security_keys(CommandSession& commands, const ScanChannelList& channels,
                                const uint8_t (&address)[6], uint8_t rx_mask, bool dual_lmac) {
    const ScanChannel* channel = nullptr;
    for (unsigned i = 0; i < channels.count; ++i) {
        if (channels.entries[i].allowed && channels.entries[i].active) {
            channel = &channels.entries[i];
            break;
        }
    }
    if (!channel)
        return "no permitted channel for the security key check";
    if (const auto* error =
            apply_channel_context(commands, *channel, rx_mask, dual_lmac, true, true))
        return error;

    // Create a local unassociated peer without querying or transmitting to an AP.
    AccessPoint peer{};
    memcpy(peer.bssid, address, sizeof(peer.bssid));
    peer.bssid[0] |= 2;
    peer.bssid[5] ^= 1;
    peer.beacon_interval_tu = 100;
    uint8_t mac[mac_context_bytes];
    prepare_authentication_mac(address, peer, mac);
    FirmwarePacket response{};
    if (commands.send(1, 0x28, mac, sizeof(mac), response) != Reply::matched)
        return "firmware rejected the security test MAC context";
    constexpr uint8_t station = 0;
    uint8_t add[peer_station_bytes];
    if (!prepare_peer_station(peer, station, add) ||
        commands.send(1, 0x18, add, sizeof(add), response) != Reply::matched ||
        !peer_station_added(response))
        return "firmware rejected the security test peer";

    uint8_t wire[key_command_bytes]{};
    constexpr CcmpKeySlot pairwise{station, 0, false}, group{station, 1, true};
    constexpr uint8_t test_key[ccmp_key_bytes]{1, 2,  3,  4,  5,  6,  7,  8,
                                               9, 10, 11, 12, 13, 14, 15, 16};
    if (!prepare_ccmp_key_install(pairwise, test_key, 0, 0, wire) ||
        !send_key_command(commands, wire))
        return "firmware did not acknowledge pairwise key installation";
    if (!prepare_ccmp_key_install(group, test_key, 1, 0, wire) || !send_key_command(commands, wire))
        return "firmware did not acknowledge group key installation";
    if (!prepare_ccmp_key_remove(group, wire) || !send_key_command(commands, wire))
        return "firmware did not acknowledge group key removal";
    if (!prepare_ccmp_key_remove(pairwise, wire) || !send_key_command(commands, wire))
        return "firmware did not acknowledge pairwise key removal";

    uint8_t remove[remove_peer_bytes];
    prepare_remove_peer(station, remove);
    if (commands.send(1, 0x19, remove, sizeof(remove), response) != Reply::matched)
        return "firmware did not remove the security test peer";
    return apply_channel_context(commands, *channel, rx_mask, dual_lmac, false);
}

template <typename Observe>
const char* wait_authentication(CommandSession& commands, unsigned deadline, const char* timeout,
                                Observe observe) {
    for (unsigned elapsed = 0; elapsed < deadline; ++elapsed) {
        if (!commands.acknowledge_pending())
            return "authentication receive queue stopped";
        for (unsigned i = 0; i < 64; ++i) {
            FirmwarePacket packet{};
            const auto result = commands.rx.next(packet);
            if (result == PacketRead::malformed)
                return "authentication receive queue is malformed";
            if (result == PacketRead::end)
                break;
            bool done = false;
            const auto* error = observe(packet, done);
            if (done || error)
                return error;
        }
        if (!commands.reg.delay(1000))
            return "authentication timer unavailable";
    }
    return timeout;
}

const char* start_management_session(CommandSession& commands) {
    uint8_t protection[session_protection_bytes];
    prepare_session_protection(true, protection);
    const auto sequence = commands.index;
    if (!commands.submit(3, 5, protection, sizeof(protection)))
        return "cannot submit session protection";
    bool acknowledged = false, started = false;
    return wait_authentication(
        commands, 100, "session protection did not start",
        [&](const FirmwarePacket& packet, bool& done) -> const char* {
            if (packet.sequence == sequence && packet.group == 0 && packet.opcode == 2)
                return "firmware rejected session protection";
            if (packet.sequence == sequence && packet.group == 3 && packet.opcode == 5)
                acknowledged = true;
            const auto event = observe_session_protection(packet);
            if (event == AuthEvent::accepted)
                started = true;
            else if (event != AuthEvent::unrelated)
                return "firmware session protection failed";
            done = acknowledged && started;
            return nullptr;
        });
}

const char* exchange_management(CommandSession& commands, PeerQueue& queue, uint32_t rate,
                                const uint8_t (&station)[6], const AccessPoint& peer,
                                const ScanChannel& channel, ManagementFrame kind,
                                const AssociationRequest& association, uint16_t& aid,
                                uint16_t& sequence) {
    const bool authentication = kind == ManagementFrame::authenticate;
    const bool leaving = kind == ManagementFrame::leave;
    const auto sent = queue;
    if (!prepare_management_frame(commands.rx.memory.authentication, sent, rate, station, peer,
                                  kind, association, sequence))
        return "cannot prepare management transmit descriptor";
    ++sequence;
    __atomic_thread_fence(__ATOMIC_RELEASE);
    commands.reg.write(command_write_pointer,
                       uint8_t(sent.write_pointer + 1) | (uint32_t(sent.id) << 16));

    bool transmitted = false, accepted = leaving;
    const char* timeout = authentication ? "open-system authentication timed out"
                          : leaving      ? "deauthentication transmit timed out"
                                         : "association exchange timed out";
    return wait_authentication(
        commands, 950, timeout, [&](const FirmwarePacket& packet, bool& done) -> const char* {
            const auto tx = observe_authentication_tx(packet, sent);
            if (tx == AuthEvent::accepted) {
                transmitted = true;
                queue.write_pointer = uint8_t(sent.write_pointer + 1);
            } else if (tx == AuthEvent::denied) {
                return authentication ? "firmware could not deliver the authentication request"
                                      : "firmware could not deliver the management frame";
            } else if (tx == AuthEvent::malformed) {
                return "firmware returned an invalid management transmit completion";
            }
            if (!accepted) {
                const auto reply =
                    authentication
                        ? observe_authentication_reply(packet, station, peer, channel.number)
                        : observe_association_reply(packet, station, peer, channel.number, aid);
                if (reply == AuthEvent::accepted)
                    accepted = true;
                else if (reply == AuthEvent::denied)
                    return authentication ? "access point refused open-system authentication"
                                          : "access point refused association";
                else if (reply == AuthEvent::malformed)
                    return authentication ? "access point returned an invalid authentication reply"
                                          : "access point returned an invalid association reply";
            }
            if (!leaving && observe_session_protection(packet) == AuthEvent::ended)
                return "session protection ended before the management exchange completed";
            done = transmitted && accepted;
            return nullptr;
        });
}

const char* exchange_arp(CommandSession& commands, PeerQueue& queue, uint32_t rate,
                         const uint8_t (&station)[6], uint8_t channel,
                         const AuthenticationTarget& target, uint16_t& sequence) {
    const auto sent = queue;
    if (!prepare_arp_request(commands.rx.memory.data_transmit, sent, rate, station, target,
                             sequence))
        return "cannot prepare the ARP request";
    ++sequence;
    __atomic_thread_fence(__ATOMIC_RELEASE);
    commands.reg.write(command_write_pointer,
                       uint8_t(sent.write_pointer + 1) | (uint32_t(sent.id) << 16));

    bool transmitted = false, received = false;
    return wait_authentication(
        commands, 900, "associated ARP exchange timed out",
        [&](const FirmwarePacket& packet, bool& done) -> const char* {
            const auto tx = observe_authentication_tx(packet, sent);
            if (tx == AuthEvent::accepted) {
                transmitted = true;
                queue.write_pointer = uint8_t(sent.write_pointer + 1);
            } else if (tx == AuthEvent::denied || tx == AuthEvent::malformed) {
                return "firmware did not confirm ARP transmission";
            }
            received |= observe_arp_response(packet, station, channel, target);
            done = transmitted && received;
            return nullptr;
        });
}

bool allocate_data_queue(CommandSession& commands, uint8_t station_id, PeerQueue management,
                         PeerQueue& data) {
    uint8_t scheduler[scheduler_command_bytes];
    FirmwarePacket reply{};
    return prepare_add_station_queue(commands.rx.memory.data_queue, station_id, scheduler,
                                     non_qos_tid) &&
           commands.send(5, 0x17, scheduler, sizeof(scheduler), reply) == Reply::matched &&
           parse_station_queue(reply, data) && data.id != management.id;
}

const char* check_associated_data(CommandSession& commands, uint8_t station_id,
                                  PeerQueue management, uint32_t rate, const uint8_t (&station)[6],
                                  uint8_t channel, const AuthenticationTarget& target,
                                  uint16_t& sequence) {
    PeerQueue data;
    if (!allocate_data_queue(commands, station_id, management, data))
        return "firmware data queue allocation failed";
    if (const auto* error = exchange_arp(commands, data, rate, station, channel, target, sequence))
        return error; // Reset the adapter before reusing the transmit buffer.
    uint8_t scheduler[scheduler_command_bytes];
    FirmwarePacket reply{};
    if (!prepare_remove_station_queue(station_id, scheduler, non_qos_tid) ||
        commands.send(5, 0x17, scheduler, sizeof(scheduler), reply) != Reply::matched ||
        !station_queue_removed(reply))
        return "firmware data queue removal failed";
    return nullptr;
}

const char* run_management_exchange(CommandSession& commands, PeerQueue queue, uint32_t rate,
                                    const uint8_t (&station)[6], const AccessPoint& peer,
                                    const ScanChannel& channel,
                                    const AssociationRequest& association, uint16_t& aid,
                                    const AuthenticationTarget* probe, LiveStation* open) {
    if (const auto* error = start_management_session(commands))
        return error;
    uint16_t sequence = 0;
    if (const auto* error =
            exchange_management(commands, queue, rate, station, peer, channel,
                                ManagementFrame::authenticate, association, aid, sequence))
        return error;
    if (association.length) {
        const auto* error =
            exchange_management(commands, queue, rate, station, peer, channel,
                                ManagementFrame::associate, association, aid, sequence);
        if (error)
            return error;
        AssociationTiming timing;
        const unsigned beacon_wait =
            max(300u, min(1000u, peer.beacon_interval_tu * 3u * 1024 / 1000));
        const auto* sync_error = wait_authentication(
            commands, beacon_wait, "associated access point beacon timed out",
            [&](const FirmwarePacket& packet, bool& done) -> const char* {
                done = observe_association_beacon(packet, peer, channel.number, timing);
                return nullptr;
            });
        uint8_t mac[mac_context_bytes];
        FirmwarePacket reply{};
        if (!sync_error) {
            prepare_associated_mac(station, peer, aid, timing, mac);
            if (commands.send(1, 0x28, mac, sizeof(mac), reply) != Reply::matched)
                sync_error = "firmware rejected the associated MAC context";
        }
        if (open) {
            if (sync_error)
                return sync_error;
            if (!allocate_data_queue(commands, 0, queue, open->queue))
                return "firmware data queue allocation failed";
            open->management = queue;
            open->peer = peer;
            open->peer.beacon_interval_tu = timing.beacon_interval_tu;
            open->channel = channel.number;
            open->rate = rate;
            open->next_sequence = sequence;
        }
        if (probe && !sync_error) {
            if (const auto* arp_error = check_associated_data(commands, 0, queue, rate, station,
                                                              channel.number, *probe, sequence))
                return arp_error;
        }
        if (!open) {
            const auto* leave_error =
                exchange_management(commands, queue, rate, station, peer, channel,
                                    ManagementFrame::leave, association, aid, sequence);
            if (sync_error)
                return sync_error;
            if (leave_error)
                return leave_error;
            prepare_authentication_mac(station, peer, mac);
            if (commands.send(1, 0x28, mac, sizeof(mac), reply) != Reply::matched)
                return "firmware could not clear the associated MAC context";
        }
    }
    uint8_t protection[session_protection_bytes];
    prepare_session_protection(false, protection);
    FirmwarePacket reply{};
    return commands.send(3, 5, protection, sizeof(protection), reply) == Reply::matched
               ? nullptr
               : "firmware could not release session protection";
}

const char* check_peer_queue(CommandSession& commands, const ScanChannelList& channels,
                             const PassiveScan& scan, const ScanChecks& checks,
                             AntennaMasks usable_antennas, PeerQueue& queue,
                             uint16_t& association_id, LiveStation* open) {
    const bool authenticate = management_exchange(checks.check);
    const AccessPoint* peer = nullptr;
    const ScanChannel* channel = nullptr;
    for (unsigned i = 0; i < scan.access_point_count; ++i) {
        const auto& ap = scan.access_points[i];
        if ((ap.capability & 3) != 1 || (peer && ap.signal_dbm <= peer->signal_dbm) ||
            (authenticate && memcmp(ap.bssid, checks.target.bssid, sizeof(ap.bssid))))
            continue;
        for (unsigned j = 0; j < channels.count; ++j) {
            const auto& candidate = channels.entries[j];
            if (candidate.allowed && candidate.active &&
                candidate.frequency_mhz == ap.frequency_mhz) {
                peer = &ap;
                channel = &candidate;
                break;
            }
        }
    }
    if (!peer)
        return authenticate
                   ? "requested access point not found on a permitted active channel"
                   : "no infrastructure access point on a channel permitted for active operation";
    uint32_t rate = 0;
    AssociationRequest association;
    if (authenticate) {
        if (!scan.elements)
            return "authentication scan information is missing";
        const auto& ies = scan.elements->records[peer - scan.access_points];
        rate = authentication_rate(ies.probe, peer->probe_ie_bytes, channel->frequency_mhz >= 5000,
                                   usable_antennas.tx);
        if (!rate)
            rate = authentication_rate(ies.beacon, peer->beacon_ie_bytes,
                                       channel->frequency_mhz >= 5000, usable_antennas.tx);
        if (!rate)
            return "no supported authentication transmit rate";
        if (checks.check != FirmwareCheck::authenticate &&
            !prepare_association_request(*peer, ies.beacon, peer->beacon_ie_bytes,
                                         channel->frequency_mhz >= 5000, association))
            return "association check requires a named open access point with supported legacy "
                   "rates";
    }
    if (const auto* error = apply_channel_context(commands, *channel, usable_antennas.rx,
                                                  checks.dual_lmac, true, true))
        return error;

    constexpr uint8_t station = 0;
    uint8_t add_station[peer_station_bytes];
    FirmwarePacket reply{};
    if (authenticate) {
        uint8_t mac[mac_context_bytes];
        prepare_authentication_mac(scan.station_address, *peer, mac);
        if (commands.send(1, 0x28, mac, sizeof(mac), reply) != Reply::matched)
            return "firmware could not select the authentication BSSID";
    }
    if (!prepare_peer_station(*peer, station, add_station) ||
        commands.send(1, 0x18, add_station, sizeof(add_station), reply) != Reply::matched ||
        !peer_station_added(reply))
        return "firmware rejected the unassociated peer station";

    uint8_t scheduler[scheduler_command_bytes];
    if (!prepare_add_station_queue(commands.rx.memory.peer_queue, station, scheduler) ||
        commands.send(5, 0x17, scheduler, sizeof(scheduler), reply) != Reply::matched ||
        !parse_station_queue(reply, queue))
        return "firmware management queue allocation failed";
    if (authenticate) {
        const auto* probe = checks.check == FirmwareCheck::data_probe ? &checks.target : nullptr;
        if (const auto* error =
                run_management_exchange(commands, queue, rate, scan.station_address, *peer,
                                        *channel, association, association_id, probe, open))
            return error;
    }
    if (open)
        return nullptr;
    if (!prepare_remove_station_queue(station, scheduler) ||
        commands.send(5, 0x17, scheduler, sizeof(scheduler), reply) != Reply::matched ||
        !station_queue_removed(reply))
        return "firmware management queue removal failed";

    uint8_t remove_station[remove_peer_bytes];
    prepare_remove_peer(station, remove_station);
    if (commands.send(1, 0x19, remove_station, sizeof(remove_station), reply) != Reply::matched)
        return "firmware peer station removal failed";
    return apply_channel_context(commands, *channel, usable_antennas.rx, checks.dual_lmac, false);
}

const char* run_passive_scan(CommandSession& commands, const ScanChannelList& channels,
                             const uint8_t (&address)[6], PassiveScan& scan, uint32_t id) {
    uint8_t request[scan_request_bytes];
    scan.access_point_count = 0;
    scan.access_points_truncated = false;
    memcpy(scan.station_address, address, sizeof(address));
    if (!prepare_scan_phase(channels, scan, request, id, all_scan_channels, {}))
        return "no permitted 2.4 or 5 GHz channels";

    PassiveScanExchange exchange(scan, commands.index, 0);
    if (!commands.submit(1, 0xd, request, sizeof(request)))
        return "cannot submit the passive scan request";
    for (uint64_t elapsed_ms = 0;; ++elapsed_ms) {
        commands.poll_scan(exchange, elapsed_ms);
        if (exchange.outcome() != ScanOutcome::pending)
            break;
        if (!commands.reg.delay(1000))
            return "passive scan timer unavailable";
    }
    switch (exchange.outcome()) {
    case ScanOutcome::complete:
        return nullptr;
    case ScanOutcome::rejected:
        return "firmware rejected the passive scan request";
    case ScanOutcome::reply_timeout:
        return "passive scan command reply timed out";
    case ScanOutcome::completion_timeout:
        return "passive scan completion timed out";
    case ScanOutcome::receive_failed:
        return "passive scan receive failed";
    case ScanOutcome::aborted:
        return "firmware aborted the passive scan";
    case ScanOutcome::malformed:
    case ScanOutcome::pending:
        return "firmware returned an invalid scan completion";
    }
    __builtin_unreachable();
}
} // namespace

AlivePacket read_alive_notification(const uint8_t* data, size_t length) {
    FirmwarePacket packet{};
    size_t offset = 0;
    PacketRead received;
    while ((received = next_firmware_packet(data, length, offset, packet)) == PacketRead::packet) {
        const auto alive = decode_alive(packet);
        if (alive != AlivePacket::missing)
            return alive;
    }
    return received == PacketRead::end ? AlivePacket::missing : AlivePacket::malformed;
}

static bool stop_adapter(const Registers& reg, bool request_dma) {
    reg.write(interrupt_mask, 0);
    bool idle = true;
    if (request_dma) {
        const bool stopped = reg.update(reset, stop_master) &&
                             reg.wait(reset, master_disabled, master_disabled, 200);
        const bool disabled = reg.io.bus_master(reg.io.context, false);
        idle = stopped && disabled;
    }
    const bool reset_done = reset_adapter(reg);
    return !request_dma || (idle && reset_done);
}

static FirmwareBootResult boot_quz(const FirmwareBootIo& io, const FirmwareBootMemory& memory,
                                   const ScanChecks* scan, LiveScanSession* live) {
    const bool open = live && scan && scan->check == FirmwareCheck::open_link;
    const bool authenticate = scan && management_exchange(scan->check);
    const bool peer_check = authenticate || (scan && scan->check == FirmwareCheck::peer_queue);
    if (peer_check && !valid_peer_queue_memory(memory.peer_queue))
        return {"invalid management queue DMA addresses", false, true};
    if (authenticate && (!valid_authentication_dma(memory.authentication) ||
                         memory.authentication.address == memory.peer_queue.descriptor_ring ||
                         memory.authentication.address == memory.peer_queue.byte_counts))
        return {"invalid authentication DMA addresses", false, true};
    if (scan && (open || scan->check == FirmwareCheck::data_probe) &&
        (!valid_peer_queue_memory(memory.data_queue) ||
         !valid_authentication_dma(memory.data_transmit) ||
         memory.data_transmit.ring == memory.authentication.ring ||
         memory.data_transmit.byte_counts == memory.authentication.byte_counts ||
         memory.data_transmit.address != memory.authentication.address ||
         memory.data_transmit.payload != memory.authentication.payload))
        return {"invalid data queue DMA addresses", false, true};
    if (!memory.context_address || memory.context_address != align_down(memory.context_address) ||
        !Dma::fits(memory.context_address, sizeof(BootContext), Dma::pci) ||
        !memory.receive_status || !memory.used_ring)
        return {"invalid startup DMA addresses", false, true};
    if (bool(memory.free_ring) != bool(memory.receive_descriptors) || (live && !memory.free_ring))
        return {"invalid receive recycling addresses", false, true};
    if ((scan && !memory.commands) ||
        (memory.commands && (!memory.command_payloads || !memory.command_dma ||
                             !Dma::fits(memory.command_dma, sizeof(CommandPayloads), Dma::pci))))
        return {"invalid command DMA addresses", false, true};
    const Registers reg{io};
    if (!claim_with_wake(reg))
        return {"PCI ownership unavailable", false, true};

    bool owned = true;
    const char* error = prepare_adapter(reg, owned);
    if (!owned)
        return {error, false, true};
    const bool request_dma = error == nullptr;
    bool alive = false;
    unsigned completed_scans = 0;
    unsigned checked_channels = 0;
    PeerQueue peer_queue{};
    uint16_t association_id = 0;
    const bool passive_check = scan && scan->check >= FirmwareCheck::passive_scan;
    const bool channel_check = scan && scan->check == FirmwareCheck::channel_context;
    const bool key_check = scan && scan->check == FirmwareCheck::security_key;
    NvmInfo info{};
    RegulatoryProfile regulatory{};
    PassiveScan passive{};
    if (scan)
        passive.elements = scan->elements;
    if (authenticate) {
        passive.filter_peer = true;
        passive.target = scan->target;
    }
    if (request_dma) {
        if (!io.bus_master(io.context, true)) {
            error = "PCI bus master did not enable";
        } else {
            __atomic_thread_fence(__ATOMIC_RELEASE);
            reg.write(context_base, uint32_t(memory.context_address));
            reg.write(context_base + 4, 0);
            reg.write(interrupt_mask, alive_interrupt | rx_interrupt | error_interrupts);
            reg.write_peripheral(cpu_start, 1);
            ReceiveReader temporary{io, memory};
            auto& rx = live ? live->receive : temporary;
            error = wait_for_alive(reg, rx);
            alive = !error;
            if (alive && memory.commands) {
                uint16_t index = 0;
                CommandSession commands{reg, rx, live ? live->next_command : index};
                error = request_nvm(commands, info);
                if (!error && passive_check)
                    error = configure_tx_antennas(commands, info, scan->antennas);
                if (!error && scan && scan->check >= FirmwareCheck::regulatory)
                    error = request_regulatory_profile(commands, info, regulatory);
                if (!error && scan)
                    error = configure_scan(commands, info, scan->antennas);
                if (!error && passive_check) {
                    uint8_t address[6];
                    error = configure_scan_station(commands, address);
                    const auto channels = scan_channel_list(info, regulatory);
                    if (!error && live) {
                        live->channels = channels;
                        memcpy(live->station_address, address, sizeof(address));
                        live->antennas = {uint8_t(info.tx_chains & scan->antennas.tx),
                                          uint8_t(info.rx_chains & scan->antennas.rx)};
                        live->dual_lmac = scan->dual_lmac;
                        if (!open) {
                            live->running = true;
                            return {
                                "live passive scan ready", alive, false, true, info, regulatory};
                        }
                    }
                    if (!error && key_check) {
                        error = check_security_keys(commands, channels, address,
                                                    info.rx_chains & scan->antennas.rx,
                                                    scan->dual_lmac);
                    } else if (!error && channel_check) {
                        error = check_channel_contexts(commands, channels,
                                                       info.rx_chains & scan->antennas.rx,
                                                       scan->dual_lmac, checked_channels);
                    } else {
                        const unsigned scans = scan->check == FirmwareCheck::rescan ? 2 : 1;
                        while (!error && completed_scans < scans) {
                            error = run_passive_scan(commands, channels, address, passive,
                                                     completed_scans);
                            if (!error)
                                ++completed_scans;
                        }
                        if (!error && peer_check)
                            error = check_peer_queue(commands, channels, passive, *scan,
                                                     {uint8_t(info.tx_chains & scan->antennas.tx),
                                                      uint8_t(info.rx_chains & scan->antennas.rx)},
                                                     peer_queue, association_id,
                                                     open ? &live->station : nullptr);
                        if (!error && open) {
                            live->running = true;
                            return {"open station ready",
                                    alive,
                                    false,
                                    true,
                                    info,
                                    regulatory,
                                    passive,
                                    completed_scans,
                                    checked_channels,
                                    peer_queue,
                                    association_id};
                        }
                    }
                }
            }
        }
    }

    const bool idle = stop_adapter(reg, request_dma);
    if (key_check && idle)
        erase_key_bytes(memory.command_payloads, sizeof(*memory.command_payloads));
    if (channel_check && !idle && !error)
        error = "operating channel check could not stop DMA";
    if (key_check && !idle && !error)
        error = "security key check could not stop DMA";
    if (authenticate && !idle && !error)
        error = "authentication check could not stop DMA";
    else if (peer_check && !idle && !error)
        error = "peer queue check could not stop DMA";
    const char* success = "firmware ALIVE received";
    if (scan && scan->check == FirmwareCheck::data_probe)
        success = "associated ARP exchange and deauthentication passed";
    else if (scan && scan->check == FirmwareCheck::associate)
        success = "open-system association, beacon synchronization, and deauthentication passed";
    else if (authenticate)
        success = "open-system authentication exchange passed";
    else if (peer_check)
        success = "peer station and management queue check passed";
    else if (key_check)
        success = "CCMP pairwise and group key commands acknowledged";
    else if (channel_check)
        success = "operating channel binding check passed";
    else if (scan && scan->check == FirmwareCheck::rescan)
        success = "two firmware passive scans complete";
    else if (passive_check)
        success = "firmware passive scan complete";
    else if (scan && scan->check == FirmwareCheck::regulatory)
        success = "firmware regulatory profile and scan configuration passed";
    else if (scan)
        success = "firmware scan configuration accepted";
    else if (memory.commands)
        success = "firmware NVM read passed";
    return {error ? error : success,
            alive,
            idle,
            !error,
            info,
            regulatory,
            passive,
            completed_scans,
            checked_channels,
            peer_queue,
            association_id};
}

FirmwareBootResult start_and_stop_quz(const FirmwareBootIo& io, const FirmwareBootMemory& memory,
                                      const ScanChecks* scan) {
    return boot_quz(io, memory, scan, nullptr);
}

FirmwareBootResult start_live_quz(LiveScanSession& session, const AntennaMasks& antennas,
                                  const AuthenticationTarget* open, ScanElementStorage* elements,
                                  bool dual_lmac) {
    if (session.running)
        return {"radio already running", true, false};
    const ScanChecks check{antennas, open ? FirmwareCheck::open_link : FirmwareCheck::live_scan,
                           elements, dual_lmac, open ? *open : AuthenticationTarget{}};
    session.station = {};
    session.join = {};
    session.leave = {};
    return boot_quz(session.io, session.receive.memory, &check, &session);
}

bool stop_live_quz(LiveScanSession& session) {
    if (!session.running)
        return true;
    session.running = false;
    session.active = false;
    session.join.phase = JoinPhase::idle;
    session.leave.phase = LeavePhase::idle;
    session.passive_channels = 0;
    return stop_adapter(Registers{session.io}, true);
}

static int submit_scan_phase(LiveScanSession& session, CommandSession& commands, uint64_t now_ms,
                             uint64_t channels, const ScanSsids& ssids) {
    uint8_t request[scan_request_bytes];
    if (!prepare_scan_phase(session.channels, session.scan, request, session.next_scan_id, channels,
                            ssids))
        return -22;
    session.exchange.restart(session.next_command, now_ms);
    if (!commands.submit(1, 0xd, request, sizeof(request)))
        return -5;
    session.active = true;
    session.next_scan_id ^= 1;
    return 0;
}

int submit_live_scan(LiveScanSession& session, ScanElementStorage& elements, uint64_t now_ms,
                     const ScanRequest& request) {
    if (!session.running)
        return -95;
    if (session.active || session.station.queue.id || session.join.phase != JoinPhase::idle)
        return -16;

    uint64_t allowed = 0, active = 0;
    for (unsigned i = 0; i < session.channels.count; ++i) {
        const auto& channel = session.channels.entries[i];
        const uint64_t bit = uint64_t(1) << i;
        if (!channel.allowed || !(request.channels & bit))
            continue;
        allowed |= bit;
        if (request.ssids.count && channel.active)
            active |= bit;
    }
    if (!allowed)
        return -22;
    session.scan.access_point_count = 0;
    session.scan.access_points_truncated = false;
    session.scan.elements = &elements;
    memcpy(session.scan.station_address, session.station_address, sizeof(session.station_address));
    const Registers reg{session.io};
    CommandSession commands{reg, session.receive, session.next_command};
    const int error = active ? submit_scan_phase(session, commands, now_ms, active, request.ssids)
                             : submit_scan_phase(session, commands, now_ms, allowed, {});
    session.passive_channels = !error && active ? allowed & ~active : 0;
    return error;
}

ScanOutcome poll_live_scan(LiveScanSession& session, uint64_t now_ms) {
    if (!session.running)
        return ScanOutcome::receive_failed;
    const Registers reg{session.io};
    CommandSession commands{reg, session.receive, session.next_command};
    if (!session.active)
        return commands.poll_idle() ? ScanOutcome::pending : ScanOutcome::receive_failed;
    commands.poll_scan(session.exchange, now_ms);
    const auto outcome = session.exchange.outcome();
    if (outcome == ScanOutcome::pending)
        return outcome;
    session.active = false;
    const uint64_t passive = session.passive_channels;
    session.passive_channels = 0;
    if (outcome == ScanOutcome::complete && passive) {
        if (submit_scan_phase(session, commands, now_ms, passive, {}))
            return ScanOutcome::receive_failed;
        return ScanOutcome::pending;
    }
    return outcome;
}

int submit_live_join(LiveScanSession& session, const PassiveScan& scan,
                     const StationRequest& request) {
    if (!session.running || !valid_peer_queue_memory(session.receive.memory.peer_queue) ||
        !valid_peer_queue_memory(session.receive.memory.data_queue) ||
        !valid_authentication_dma(session.receive.memory.authentication) ||
        !valid_authentication_dma(session.receive.memory.data_transmit))
        return -95;
    if (session.leave.phase != LeavePhase::idle)
        return -16;
    if (session.station.queue.id)
        return -106;
    if (session.active || session.join.phase != JoinPhase::idle)
        return -16;
    if (!request.ssid.length || request.ssid.length > sizeof(request.ssid.bytes))
        return -22;
    if (!scan.elements || scan.status != PassiveScan::Status::complete)
        return -2;

    bool specified_bssid = false;
    for (const auto byte : request.bssid)
        specified_bssid |= byte != 0;
    StationJoin candidate;
    unsigned preferred = 0;
    for (unsigned i = 0; i < scan.access_point_count; ++i) {
        const auto& peer = scan.access_points[i];
        const unsigned preference =
            (!specified_bssid && !memcmp(peer.bssid, request.bssid_hint, sizeof(peer.bssid)) ? 2
                                                                                             : 0) +
            (!request.frequency_mhz && peer.frequency_mhz == request.frequency_hint ? 1 : 0);
        if (peer.ssid_length != request.ssid.length ||
            memcmp(peer.ssid, request.ssid.bytes, request.ssid.length) ||
            (specified_bssid && memcmp(peer.bssid, request.bssid, sizeof(peer.bssid))) ||
            (request.frequency_mhz && peer.frequency_mhz != request.frequency_mhz) ||
            (candidate.rate &&
             (preference < preferred ||
              (preference == preferred && peer.signal_dbm <= candidate.peer.signal_dbm))))
            continue;
        for (unsigned j = 0; j < session.channels.count; ++j) {
            const auto& channel = session.channels.entries[j];
            if (!channel.allowed || !channel.active || channel.frequency_mhz != peer.frequency_mhz)
                continue;
            const bool high = channel.frequency_mhz >= 5000;
            const auto& elements = scan.elements->records[i];
            AssociationRequest association;
            if (!prepare_association_request(peer, elements.beacon, peer.beacon_ie_bytes, high,
                                             association, request.extra, request.extra_bytes))
                break;
            const auto rate = authentication_rate(elements.beacon, peer.beacon_ie_bytes, high,
                                                  session.antennas.tx);
            if (!rate)
                break;
            candidate.peer = peer;
            candidate.channel = channel;
            candidate.association = association;
            candidate.rate = rate;
            preferred = preference;
            break;
        }
    }
    if (!candidate.rate)
        return -2;
    candidate.phase = JoinPhase::phy;
    candidate.controlled_port = request.controlled_port;
    session.join = candidate;
    return 0;
}

namespace {
template <typename Operation>
bool submit_operation(CommandSession& commands, Operation& operation, uint8_t group, uint8_t opcode,
                      const uint8_t* bytes, size_t length) {
    operation.command_sequence = commands.index;
    operation.group = group;
    operation.opcode = opcode;
    return commands.submit(group, opcode, bytes, length);
}

bool begin_join_phase(LiveScanSession& session, CommandSession& commands, uint64_t now_ms) {
    auto& join = session.join;
    join.submitted = true;
    join.acknowledged = join.indicated = false;
    join.deadline = now_ms + 1000;
    switch (join.phase) {
    case JoinPhase::phy:
    case JoinPhase::chains:
    case JoinPhase::fifo:
    case JoinPhase::bind: {
        constexpr ChannelStep steps[]{ChannelStep::add_phy, ChannelStep::rx_chains,
                                      ChannelStep::initialize_fifo, ChannelStep::bind};
        const auto step = steps[unsigned(join.phase) - unsigned(JoinPhase::phy)];
        const auto cmd =
            channel_command(step, join.channel, session.antennas.rx, session.dual_lmac);
        return submit_operation(commands, join, cmd.group, cmd.opcode, cmd.bytes, cmd.size);
    }
    case JoinPhase::select_mac:
    case JoinPhase::associated_mac: {
        uint8_t wire[mac_context_bytes];
        if (join.phase == JoinPhase::select_mac)
            prepare_authentication_mac(session.station_address, join.peer, wire);
        else
            prepare_associated_mac(session.station_address, join.peer, join.aid, join.timing, wire);
        return submit_operation(commands, join, 1, 0x28, wire, sizeof(wire));
    }
    case JoinPhase::add_peer: {
        uint8_t wire[peer_station_bytes];
        return prepare_peer_station(join.peer, 0, wire) &&
               submit_operation(commands, join, 1, 0x18, wire, sizeof(wire));
    }
    case JoinPhase::management_queue:
    case JoinPhase::data_queue: {
        const bool data = join.phase == JoinPhase::data_queue;
        const auto& memory = commands.rx.memory;
        uint8_t wire[scheduler_command_bytes];
        return prepare_add_station_queue(data ? memory.data_queue : memory.peer_queue, 0, wire,
                                         data ? non_qos_tid : management_tid) &&
               submit_operation(commands, join, 5, 0x17, wire, sizeof(wire));
    }
    case JoinPhase::protect:
    case JoinPhase::release_protection: {
        uint8_t wire[session_protection_bytes];
        prepare_session_protection(join.phase == JoinPhase::protect, wire);
        return submit_operation(commands, join, 3, 5, wire, sizeof(wire));
    }
    case JoinPhase::authenticate:
    case JoinPhase::associate: {
        const auto kind = join.phase == JoinPhase::authenticate ? ManagementFrame::authenticate
                                                                : ManagementFrame::associate;
        if (!prepare_management_frame(commands.rx.memory.authentication, join.management, join.rate,
                                      session.station_address, join.peer, kind, join.association,
                                      join.sequence))
            return false;
        ++join.sequence;
        __atomic_thread_fence(__ATOMIC_RELEASE);
        commands.reg.write(command_write_pointer, uint8_t(join.management.write_pointer + 1) |
                                                      (uint32_t(join.management.id) << 16));
        return true;
    }
    case JoinPhase::beacon:
        return true;
    case JoinPhase::idle:
        return false;
    }
    __builtin_unreachable();
}
} // namespace

namespace {
enum class JoinProgress { waiting, ready, rejected, failed };

JoinProgress observe_join_packet(LiveScanSession& session, const FirmwarePacket& packet) {
    auto& join = session.join;
    if (join.phase == JoinPhase::beacon)
        return observe_association_beacon(packet, join.peer, join.channel.number, join.timing)
                   ? JoinProgress::ready
                   : JoinProgress::waiting;
    if (join.phase == JoinPhase::authenticate || join.phase == JoinPhase::associate) {
        const auto tx = observe_authentication_tx(packet, join.management);
        if (tx == AuthEvent::denied)
            return JoinProgress::rejected;
        if (tx == AuthEvent::malformed || observe_session_protection(packet) == AuthEvent::ended)
            return JoinProgress::failed;
        join.acknowledged |= tx == AuthEvent::accepted;
        const auto response =
            join.phase == JoinPhase::authenticate
                ? observe_authentication_reply(packet, session.station_address, join.peer,
                                               join.channel.number)
                : observe_association_reply(packet, session.station_address, join.peer,
                                            join.channel.number, join.aid);
        if (response == AuthEvent::denied)
            return JoinProgress::rejected;
        if (response == AuthEvent::malformed)
            return JoinProgress::failed;
        join.indicated |= response == AuthEvent::accepted;
        if (join.acknowledged && join.indicated) {
            ++join.management.write_pointer;
            return JoinProgress::ready;
        }
        return JoinProgress::waiting;
    }
    if (packet.sequence == join.command_sequence) {
        if (packet.group == 0 && packet.opcode == 2)
            return JoinProgress::rejected;
        join.acknowledged |= packet.group == join.group && packet.opcode == join.opcode;
    }
    if (join.phase == JoinPhase::protect) {
        const auto event = observe_session_protection(packet);
        if (event != AuthEvent::accepted && event != AuthEvent::unrelated)
            return JoinProgress::failed;
        join.indicated |= event == AuthEvent::accepted;
        return join.acknowledged && join.indicated ? JoinProgress::ready : JoinProgress::waiting;
    }
    if (!join.acknowledged)
        return JoinProgress::waiting;
    switch (join.phase) {
    case JoinPhase::bind:
        if (!binding_succeeded(packet))
            return JoinProgress::rejected;
        break;
    case JoinPhase::add_peer:
        if (!peer_station_added(packet))
            return JoinProgress::rejected;
        break;
    case JoinPhase::management_queue:
        if (!parse_station_queue(packet, join.management))
            return JoinProgress::rejected;
        break;
    case JoinPhase::data_queue:
        if (!parse_station_queue(packet, join.data) || join.data.id == join.management.id)
            return JoinProgress::rejected;
        break;
    default:
        break;
    }
    return JoinProgress::ready;
}
} // namespace

JoinOutcome poll_live_join(LiveScanSession& session, uint64_t now_ms) {
    auto& join = session.join;
    if (join.phase == JoinPhase::idle)
        return JoinOutcome::idle;
    const Registers reg{session.io};
    CommandSession commands{reg, session.receive, session.next_command};
    if (!commands.acknowledge_pending() ||
        (!join.submitted && !begin_join_phase(session, commands, now_ms)))
        return JoinOutcome::failed;
    for (unsigned i = 0; i < 64; ++i) {
        FirmwarePacket packet{};
        const auto result = session.receive.next(packet);
        if (result == PacketRead::malformed)
            return JoinOutcome::failed;
        if (result == PacketRead::end)
            break;
        switch (observe_join_packet(session, packet)) {
        case JoinProgress::waiting:
            continue;
        case JoinProgress::failed:
            return JoinOutcome::failed;
        case JoinProgress::rejected:
            return JoinOutcome::rejected;
        case JoinProgress::ready:
            if (join.phase == JoinPhase::release_protection) {
                session.station.peer = join.peer;
                session.station.peer.beacon_interval_tu = join.timing.beacon_interval_tu;
                session.station.queue = join.data;
                session.station.management = join.management;
                session.station.channel = join.channel.number;
                session.station.rate = join.rate;
                session.station.next_sequence = join.sequence;
                session.station.port_authorized = !join.controlled_port;
                join.phase = JoinPhase::idle;
                return JoinOutcome::connected;
            }
            join.phase = JoinPhase(unsigned(join.phase) + 1);
            join.submitted = false;
            return JoinOutcome::pending;
        }
    }
    return now_ms < join.deadline ? JoinOutcome::pending : JoinOutcome::timeout;
}

int submit_live_leave(LiveScanSession& session, uint16_t reason) {
    if (!reason)
        return -22;
    if (session.leave.phase != LeavePhase::idle || session.join.phase != JoinPhase::idle)
        return -16;
    if (!session.running)
        return -95;
    if (!session.station.queue.id)
        return 0;
    session.leave = {LeavePhase::drain, reason};
    return 0;
}

namespace {
bool begin_leave_phase(LiveScanSession& session, CommandSession& commands, uint64_t now_ms) {
    auto& leave = session.leave;
    const auto& station = session.station;
    leave.submitted = true;
    leave.deadline = now_ms + 1000;
    switch (leave.phase) {
    case LeavePhase::deauthenticate:
        if (!prepare_management_frame(commands.rx.memory.authentication, station.management,
                                      station.rate, session.station_address, station.peer,
                                      ManagementFrame::leave, {}, station.next_sequence,
                                      leave.reason))
            return false;
        __atomic_thread_fence(__ATOMIC_RELEASE);
        commands.reg.write(command_write_pointer, uint8_t(station.management.write_pointer + 1) |
                                                      (uint32_t(station.management.id) << 16));
        return true;
    case LeavePhase::clear_mac: {
        uint8_t wire[mac_context_bytes];
        prepare_scan_station(session.station_address, wire);
        wire[4] = 2; // Modify the existing MAC context.
        return submit_operation(commands, leave, 1, 0x28, wire, sizeof(wire));
    }
    case LeavePhase::remove_data:
    case LeavePhase::remove_management: {
        uint8_t wire[scheduler_command_bytes];
        const auto tid = leave.phase == LeavePhase::remove_data ? non_qos_tid : management_tid;
        return prepare_remove_station_queue(0, wire, tid) &&
               submit_operation(commands, leave, 5, 0x17, wire, sizeof(wire));
    }
    case LeavePhase::remove_peer: {
        uint8_t wire[remove_peer_bytes];
        prepare_remove_peer(0, wire);
        return submit_operation(commands, leave, 1, 0x19, wire, sizeof(wire));
    }
    case LeavePhase::unbind:
    case LeavePhase::remove_phy: {
        ScanChannel channel{};
        channel.number = station.channel;
        channel.frequency_mhz = station.peer.frequency_mhz;
        const auto step =
            leave.phase == LeavePhase::unbind ? ChannelStep::unbind : ChannelStep::remove_phy;
        const auto command = channel_command(step, channel, session.antennas.rx, session.dual_lmac);
        return submit_operation(commands, leave, command.group, command.opcode, command.bytes,
                                command.size);
    }
    case LeavePhase::drain:
    case LeavePhase::idle:
        return false;
    }
    __builtin_unreachable();
}

AuthEvent observe_leave_packet(const LiveScanSession& session, const FirmwarePacket& packet) {
    const auto& leave = session.leave;
    if (leave.phase == LeavePhase::drain)
        return observe_authentication_tx(packet, session.station.queue);
    if (leave.phase == LeavePhase::deauthenticate)
        return observe_authentication_tx(packet, session.station.management);
    if (packet.sequence != leave.command_sequence)
        return AuthEvent::unrelated;
    if (packet.group == 0 && packet.opcode == 2)
        return AuthEvent::malformed;
    if (packet.group != leave.group || packet.opcode != leave.opcode)
        return AuthEvent::unrelated;
    if (((leave.phase == LeavePhase::remove_data || leave.phase == LeavePhase::remove_management) &&
         !station_queue_removed(packet)) ||
        (leave.phase == LeavePhase::unbind && !binding_succeeded(packet)))
        return AuthEvent::malformed;
    return AuthEvent::accepted;
}
} // namespace

LeaveOutcome poll_live_leave(LiveScanSession& session, uint64_t now_ms, void* context,
                             void (*complete)(void*, size_t, bool)) {
    auto& leave = session.leave;
    auto& station = session.station;
    const Registers reg{session.io};
    CommandSession commands{reg, session.receive, session.next_command};
    if (!commands.acknowledge_pending())
        return LeaveOutcome::failed;
    if (leave.phase == LeavePhase::drain) {
        if (!station.pending_bytes)
            leave.phase = LeavePhase::deauthenticate;
        else
            leave.deadline = station.transmit_deadline;
    }
    if (leave.phase != LeavePhase::drain && !leave.submitted &&
        !begin_leave_phase(session, commands, now_ms))
        return LeaveOutcome::failed;
    for (unsigned i = 0; i < 64; ++i) {
        FirmwarePacket packet{};
        const auto result = session.receive.next(packet);
        if (result == PacketRead::malformed)
            return LeaveOutcome::failed;
        if (result == PacketRead::end)
            break;
        const auto event = observe_leave_packet(session, packet);
        if (event == AuthEvent::unrelated)
            continue;
        if (event != AuthEvent::accepted && event != AuthEvent::denied)
            return LeaveOutcome::failed;
        // A failed over-the-air transmission still returns its DMA buffer.
        if (leave.phase == LeavePhase::drain) {
            const auto bytes = station.pending_bytes;
            station.pending_bytes = 0;
            complete(context, bytes, event == AuthEvent::denied);
        }
        if (leave.phase == LeavePhase::remove_phy) {
            station = {};
            leave = {};
            return LeaveOutcome::disconnected;
        }
        leave.phase = LeavePhase(unsigned(leave.phase) + 1);
        leave.submitted = false;
        return LeaveOutcome::pending;
    }
    return now_ms < leave.deadline ? LeaveOutcome::pending : LeaveOutcome::failed;
}

namespace {
bool allows_station_data(const LiveStation& station, const uint8_t* frame, size_t length) {
    return station.port_authorized ||
           (frame && length >= 14 && frame[12] == 0x88 && frame[13] == 0x8e);
}
} // namespace

int submit_live_data(LiveScanSession& session, const uint8_t* frame, size_t length,
                     uint64_t now_ms) {
    auto& station = session.station;
    if (!session.running || !station.queue.id || session.leave.phase != LeavePhase::idle)
        return -95;
    if (!allows_station_data(station, frame, length))
        return -13;
    if (station.pending_bytes)
        return -11;
    if (!prepare_station_data(session.receive.memory.data_transmit, station.queue, station.rate,
                              session.station_address, station.peer.bssid, frame, length,
                              station.next_sequence))
        return -22;
    ++station.next_sequence;
    station.pending_bytes = length;
    station.transmit_deadline = now_ms + 1000;
    __atomic_thread_fence(__ATOMIC_RELEASE);
    Registers{session.io}.write(command_write_pointer, uint8_t(station.queue.write_pointer + 1) |
                                                           (uint32_t(station.queue.id) << 16));
    return 0;
}

bool poll_live_station(LiveScanSession& session, uint64_t now_ms, void* context,
                       void (*receive)(void*, const uint8_t*, size_t),
                       void (*complete)(void*, size_t, bool)) {
    auto& station = session.station;
    if (!session.running || !station.queue.id)
        return false;
    const Registers reg{session.io};
    CommandSession commands{reg, session.receive, session.next_command};
    if (!commands.acknowledge_pending())
        return false;
    const uint64_t beacon_timeout = max(3000u, 8u * station.peer.beacon_interval_tu * 1024 / 1000);
    if (!station.beacon_deadline)
        station.beacon_deadline = now_ms + beacon_timeout;
    uint8_t frame[station_frame_bytes];
    for (unsigned i = 0; i < 64; ++i) {
        FirmwarePacket packet{};
        const auto result = session.receive.next(packet);
        if (result == PacketRead::malformed)
            return false;
        if (result == PacketRead::end)
            break;
        if (observe_station_disconnect(packet, session.station_address, station.peer,
                                       station.channel))
            return false;
        if (station.pending_bytes) {
            const auto tx = observe_authentication_tx(packet, station.queue);
            if (tx == AuthEvent::malformed)
                return false;
            if (tx == AuthEvent::accepted || tx == AuthEvent::denied) {
                const auto bytes = station.pending_bytes;
                station.pending_bytes = 0;
                ++station.queue.write_pointer;
                complete(context, bytes, tx == AuthEvent::denied);
            }
        }
        AssociationTiming timing;
        if (observe_association_beacon(packet, station.peer, station.channel, timing))
            station.beacon_deadline = now_ms + beacon_timeout;
        if (const auto bytes = receive_station_data(packet, session.station_address,
                                                    station.peer.bssid, station.channel, frame);
            bytes && allows_station_data(station, frame, bytes))
            receive(context, frame, bytes);
    }
    return now_ms < station.beacon_deadline &&
           (!station.pending_bytes || now_ms < station.transmit_deadline);
}
} // namespace ax::IntelWifi
