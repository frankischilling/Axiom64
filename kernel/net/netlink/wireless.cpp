// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/net/netlink/wireless.cpp
 * @brief   Linux nl80211 queries and scan requests for the AX201.
 * @author  frankischilling
 * @date    2026-11-23
 *
 * Copyright (C) 2026 frankischilling
 */
#include "drivers/net/intel_wifi_live.hpp"
#include "net/netlink.hpp"
#include "net/netlink_wireless.hpp"

namespace ax {
namespace {
enum Attribute : uint16_t {
    wiphy = 1,
    wiphy_name = 2,
    ifindex = 3,
    ifname = 4,
    iftype = 5,
    mac = 6,
    key_data = 7,
    key_index = 8,
    key_cipher = 9,
    key_sequence = 10,
    wiphy_bands = 22,
    ht_capability = 31,
    supported_iftypes = 32,
    frequency_mhz = 38,
    association_ies = 42,
    max_num_scan_ssids = 43,
    scan_frequencies = 44,
    scan_ssids = 45,
    generation = 46,
    bss = 47,
    supported_commands = 50,
    ssid = 52,
    auth_type = 53,
    reason_code = 54,
    key_type = 55,
    cipher_suites = 57,
    timed_out = 65,
    use_mfp = 66,
    station_flags = 67,
    control_port = 68,
    privacy = 70,
    disconnected_by_ap = 71,
    status_code = 72,
    pairwise_cipher = 73,
    group_cipher = 74,
    wpa_versions = 75,
    akm_suites = 76,
    request_ies = 77,
    response_ies = 78,
    key_bundle = 80,
    control_port_ethertype = 102,
    ht_capability_mask = 148,
    wdev = 153,
    vht_capability = 157,
    scan_flags = 158,
    vht_capability_mask = 176,
    mac_hint = 200,
    frequency_hint = 201,
    socket_owner = 204,
    mlo_support = nl80211_max_attribute,
};

enum BssAttribute : uint16_t {
    bssid = 1,
    frequency = 2,
    beacon_interval = 4,
    capability = 5,
    information_elements = 6,
    signal_mbm = 7,
    bss_status = 9,
    beacon_elements = 11,
    probe_response_data = 14,
};

constexpr uint32_t station = 2;
constexpr uint32_t scan_colocated_6ghz = 1u << 14;
constexpr uint64_t device_id = 1;
constexpr uint16_t multipart = 2, dump_flags = 0x300;
constexpr uint8_t new_wiphy = 3, new_interface = 7, new_scan_results = 34, scan_aborted = 35;
constexpr size_t radio_reply_size = 2048;
// Each channel needs at most 24 bytes, and band headers and rates fit in 512.
static_assert(radio_reply_size >= 24 * IntelWifi::scan_channel_limit + 512);

enum BandAttribute : uint16_t { band_frequencies = 1, band_rates = 2 };

enum RateAttribute : uint16_t { rate_tenths_mbps = 1, rate_short_preamble = 2 };

enum FrequencyAttribute : uint16_t {
    center_frequency = 1,
    frequency_disabled = 2,
    frequency_no_ir = 3,
    frequency_radar = 5,
    frequency_indoor = 14,
};

struct AttributeHeader {
    uint16_t length, type;
};

class Message {
    uint8_t* output;
    size_t used = sizeof(NetlinkHeader) + 4;

    void put(size_t offset, const void* data, size_t length) const {
        if (output && length)
            memcpy(output + offset, data, length);
    }

  public:
    explicit Message(void* destination) : output(static_cast<uint8_t*>(destination)) {
    }

    void attr(uint16_t type, const void* data, size_t length) {
        const AttributeHeader header{uint16_t(sizeof(header) + length), type};
        put(used, &header, sizeof(header));
        put(used + sizeof(header), data, length);
        constexpr uint8_t zeros[3]{};
        const size_t padding = -length & 3;
        put(used + header.length, zeros, padding);
        used += header.length + padding;
    }

    template <typename T> void value(uint16_t type, const T& data) {
        attr(type, &data, sizeof(data));
    }

    size_t begin_nested(uint16_t type) {
        const size_t offset = used;
        attr(type | 0x8000, nullptr, 0);
        return offset;
    }

    void end_nested(size_t offset) {
        const uint16_t length = uint16_t(used - offset);
        put(offset, &length, sizeof(length));
    }

    size_t finish(uint8_t command, uint32_t seq, uint32_t port, bool dump) const {
        const NetlinkHeader header{uint32_t(used), nl80211_family, uint16_t(dump ? multipart : 0),
                                   seq, port};
        const uint8_t generic[4]{command, 1, 0, 0};
        put(0, &header, sizeof(header));
        put(sizeof(header), generic, sizeof(generic));
        return used;
    }
};

struct StationAttributes {
    IntelWifi::StationRequest connection{};
    uint16_t reason = 3;
    bool owned = false, authorized = false;
};

int select_association_elements(const uint8_t* bytes, size_t size,
                                IntelWifi::StationRequest& request) {
    if (size > sizeof(request.extra))
        return -22;
    unsigned seen = 0;
    for (size_t offset = 0; offset < size;) {
        if (size - offset < 2 || bytes[offset + 1] > size - offset - 2)
            return -22;
        const auto id = bytes[offset];
        const auto length = bytes[offset + 1];
        const unsigned flag = id == 59 ? 1 : id == 127 ? 2 : id == IntelWifi::rsn_element ? 4 : 0;
        if (!flag)
            return -95;
        if (!length || (seen & flag))
            return -22;
        seen |= flag;
        offset += 2 + length;
    }
    if (size)
        memcpy(request.extra, bytes, size);
    request.extra_bytes = unsigned(size);
    return 0;
}

int select_station_request(const uint8_t* bytes, size_t length, unsigned index, uint8_t command,
                           StationAttributes& request) {
    constexpr uint32_t authorized_flag = 1u << 1;
    constexpr unsigned enterprise_akm = 1, personal_akm = 2;
    bool seen[mlo_support + 1]{};
    unsigned allowed_akms = 0;
    auto& connection = request.connection;
    while (length) {
        if (length < sizeof(AttributeHeader))
            return -22;
        AttributeHeader field;
        memcpy(&field, bytes, sizeof(field));
        const size_t aligned = (size_t(field.length) + 3) & ~size_t(3);
        if (field.length < sizeof(field) || aligned > length || (field.type & 0xc000))
            return -22;
        const auto* value = bytes + sizeof(field);
        const size_t size = field.length - sizeof(field);
        if (field.type > mlo_support)
            return -95;
        const bool device = field.type == ifindex || field.type == wdev;
        if (command == nl80211_disconnect && !device && field.type != reason_code)
            return -95;
        if (command == nl80211_set_station && !device && field.type != mac &&
            field.type != station_flags)
            return -95;
        // Supplicants can send both names for the same socket-owner flag.
        if (seen[field.type] && field.type != socket_owner)
            return -22;
        seen[field.type] = true;
        switch (field.type) {
        case ifindex:
        case frequency_mhz:
        case frequency_hint:
        case auth_type:
        case use_mfp:
        case pairwise_cipher:
        case group_cipher:
        case wpa_versions: {
            uint32_t number;
            if (size != sizeof(number))
                return -22;
            memcpy(&number, value, sizeof(number));
            if (field.type == ifindex && number != index)
                return -19;
            if ((field.type == auth_type || field.type == use_mfp) && number != 0)
                return -95;
            if ((field.type == pairwise_cipher || field.type == group_cipher) &&
                number != IntelWifi::ccmp_suite)
                return -95;
            if (field.type == wpa_versions && number != 2)
                return -95;
            if (field.type == frequency_mhz || field.type == frequency_hint) {
                if (!number)
                    return -22;
                (field.type == frequency_mhz ? connection.frequency_mhz
                                             : connection.frequency_hint) = number;
            }
            break;
        }
        case akm_suites:
            if (!size || size % sizeof(uint32_t))
                return -22;
            for (size_t offset = 0; offset < size; offset += sizeof(uint32_t)) {
                uint32_t suite;
                memcpy(&suite, value + offset, sizeof(suite));
                if (suite == IntelWifi::enterprise_suite)
                    allowed_akms |= enterprise_akm;
                else if (suite == IntelWifi::personal_suite)
                    allowed_akms |= personal_akm;
            }
            if (!allowed_akms)
                return -95;
            break;
        case wdev: {
            uint64_t id;
            if (size != sizeof(id))
                return -22;
            memcpy(&id, value, sizeof(id));
            if (id != device_id)
                return -19;
            break;
        }
        case mac:
        case mac_hint:
            if (size != sizeof(connection.bssid) || (value[0] & 1))
                return -22;
            if (!(value[0] | value[1] | value[2] | value[3] | value[4] | value[5]))
                return -22;
            memcpy(field.type == mac ? connection.bssid : connection.bssid_hint, value, size);
            break;
        case ssid:
            if (!size || size > sizeof(connection.ssid.bytes))
                return -22;
            memcpy(connection.ssid.bytes, value, size);
            connection.ssid.length = uint8_t(size);
            break;
        case reason_code:
            if (command != nl80211_disconnect)
                return -95;
            if (size != sizeof(request.reason))
                return -22;
            memcpy(&request.reason, value, sizeof(request.reason));
            if (!request.reason)
                return -22;
            break;
        case association_ies:
            if (const int error = select_association_elements(value, size, connection))
                return error;
            break;
        case ht_capability:
        case ht_capability_mask:
        case vht_capability:
        case vht_capability_mask:
            // The current association uses legacy rates, so there are no HT/VHT fields to mask.
            if (size !=
                (field.type == ht_capability || field.type == ht_capability_mask ? 26u : 12u))
                return -22;
            break;
        case socket_owner:
        case control_port:
        case mlo_support:
        case privacy:
            if (size)
                return -22;
            request.owned |= field.type == socket_owner;
            connection.controlled_port |= field.type == control_port;
            break;
        case control_port_ethertype: {
            uint16_t type;
            if (size != sizeof(type))
                return -22;
            memcpy(&type, value, sizeof(type));
            if (type != 0x888e)
                return -95;
            break;
        }
        case station_flags: {
            uint32_t flags[2]{};
            if (command != nl80211_set_station)
                return -95;
            if (size != sizeof(flags))
                return -22;
            memcpy(flags, value, sizeof(flags));
            if (flags[0] != authorized_flag || (flags[1] & ~authorized_flag))
                return -95;
            request.authorized = flags[1] != 0;
            break;
        }
        default:
            return -95;
        }
        bytes += aligned;
        length -= aligned;
    }
    if (!seen[ifindex] && !seen[wdev])
        return -22;
    if (command == nl80211_connect &&
        (!seen[ssid] || (seen[ht_capability] && !seen[ht_capability_mask]) ||
         (seen[vht_capability] && !seen[vht_capability_mask])))
        return -22;
    if (command == nl80211_connect) {
        using IntelWifi::RsnAkm;
        const bool rsn = seen[akm_suites];
        if (rsn && (!seen[wpa_versions] || !seen[pairwise_cipher] || !seen[group_cipher]))
            return -22;
        // The driver gets a list of permitted suites and the RSN element for this attempt.
        // Use the selected suite in the element and require it to be in that list.
        if ((allowed_akms & enterprise_akm) &&
            IntelWifi::station_rsn_matches(connection.extra, connection.extra_bytes,
                                           RsnAkm::enterprise))
            connection.akm = RsnAkm::enterprise;
        else if ((allowed_akms & personal_akm) &&
                 IntelWifi::station_rsn_matches(connection.extra, connection.extra_bytes,
                                                RsnAkm::personal))
            connection.akm = RsnAkm::personal;
        else if (rsn || seen[wpa_versions] || seen[pairwise_cipher] || seen[group_cipher] ||
                 seen[privacy] ||
                 !IntelWifi::station_rsn_matches(connection.extra, connection.extra_bytes,
                                                 RsnAkm::open))
            return -95;
    }
    if (command == nl80211_set_station && (!seen[mac] || !seen[station_flags]))
        return -22;
    return 0;
}

enum KeyField : unsigned { material = 1, index_field, cipher, sequence, type_field = 7, mode = 9 };

struct KeyAttributes {
    IntelWifi::StationKeyRequest request{};
    uint32_t type = 0;
    unsigned fields = 0;
};

int unpack_key_field(KeyAttributes& key, unsigned field, const uint8_t* bytes, size_t size) {
    if (field != material && field != index_field && field != cipher && field != sequence &&
        field != type_field && field != mode)
        return -95;
    if (key.fields & (1u << field))
        return -22;
    key.fields |= 1u << field;
    switch (field) {
    case material:
        if (size != IntelWifi::ccmp_key_bytes)
            return -22;
        key.request.material = bytes;
        break;
    case index_field:
        if (size != 1)
            return -22;
        key.request.index = bytes[0];
        break;
    case sequence:
        if (size != 6)
            return -22;
        for (unsigned i = 0; i < size; ++i)
            key.request.receive_sequence |= uint64_t(bytes[i]) << (8 * i);
        break;
    case mode:
        if (size != 1)
            return -22;
        if (bytes[0])
            return -95;
        break;
    case cipher:
    case type_field: {
        uint32_t value;
        if (size != sizeof(value))
            return -22;
        memcpy(&value, bytes, size);
        if (field == cipher && value != IntelWifi::ccmp_suite)
            return -95;
        if (field == type_field) {
            if (value > 1)
                return -95;
            key.type = value;
        }
        break;
    }
    }
    return 0;
}

int select_key_request(const uint8_t* bytes, size_t length, unsigned expected_index, bool install,
                       KeyAttributes& key) {
    bool interface = false, device = false, peer = false, nested = false;
    const uint8_t* inner = nullptr;
    size_t inner_bytes = 0;
    while (length || inner_bytes) {
        if (!length) {
            bytes = inner;
            length = inner_bytes;
            inner_bytes = 0;
            nested = true;
        }
        if (length < sizeof(AttributeHeader))
            return -22;
        AttributeHeader attr;
        memcpy(&attr, bytes, sizeof(attr));
        const size_t aligned = (size_t(attr.length) + 3) & ~size_t(3);
        if (attr.length < sizeof(attr) || aligned > length)
            return -22;
        const auto* value = bytes + sizeof(attr);
        const size_t size = attr.length - sizeof(attr);
        bytes += aligned;
        length -= aligned;
        if (nested) {
            if (const int error = unpack_key_field(key, attr.type, value, size))
                return error;
            continue;
        }
        switch (attr.type) {
        case ifindex: {
            uint32_t id;
            if (interface || size != sizeof(id))
                return -22;
            memcpy(&id, value, size);
            if (id != expected_index)
                return -19;
            interface = true;
            break;
        }
        case wdev: {
            uint64_t id;
            if (device || size != sizeof(id))
                return -22;
            memcpy(&id, value, size);
            if (id != device_id)
                return -19;
            device = true;
            break;
        }
        case mac:
            if (peer || size != sizeof(key.request.peer) || (value[0] & 1))
                return -22;
            memcpy(key.request.peer, value, size);
            peer = true;
            break;
        case key_bundle:
        case key_bundle | 0x8000:
            if (inner || !size || key.fields)
                return -22;
            inner = value;
            inner_bytes = size;
            break;
        default: {
            if (inner)
                return -22;
            const unsigned field = attr.type >= key_data && attr.type <= key_sequence
                                       ? attr.type - key_data + material
                                   : attr.type == key_type ? unsigned(type_field)
                                                           : 0;
            if (const int error = unpack_key_field(key, field, value, size))
                return error;
            break;
        }
        }
    }
    constexpr unsigned identity = (1u << index_field) | (1u << type_field);
    constexpr unsigned install_fields = (1u << material) | (1u << cipher);
    if ((!interface && !device) || !(key.fields & (1u << index_field)) || key.request.index >= 8 ||
        (install ? (key.fields & install_fields) != install_fields : (key.fields & ~identity)))
        return -22;
    key.request.group = (key.fields & (1u << type_field)) ? key.type == 0 : !peer;
    if (key.request.group == peer)
        return -22;
    if (install && (key.request.index >= 4 || (!key.request.group && key.request.index)))
        return -95;
    return 0;
}

int select_frequencies(const uint8_t* bytes, size_t length, uint64_t& channels) {
    constexpr size_t entry_bytes = sizeof(AttributeHeader) + sizeof(uint32_t);
    if (!length || length % entry_bytes)
        return -22;
    const auto& list = IntelWifi::scan_channel_inventory();
    uint64_t seen = 0;
    channels = 0;
    for (size_t offset = 0; offset < length; offset += entry_bytes) {
        AttributeHeader field;
        uint32_t mhz;
        memcpy(&field, bytes + offset, sizeof(field));
        memcpy(&mhz, bytes + offset + sizeof(field), sizeof(mhz));
        if (field.length != entry_bytes || (field.type & 0xc000))
            return -22;
        unsigned i = 0;
        while (i < list.count && list.entries[i].frequency_mhz != mhz)
            ++i;
        const uint64_t bit = uint64_t(1) << i;
        if (i == list.count || (seen & bit))
            return -22;
        seen |= bit;
        if (list.entries[i].allowed)
            channels |= bit;
    }
    return channels ? 0 : -22;
}

int select_ssids(const uint8_t* bytes, size_t length, IntelWifi::ScanSsids& ssids) {
    unsigned count = 0;
    while (length) {
        if (length < sizeof(AttributeHeader) || ++count > IntelWifi::scan_ssid_limit)
            return -22;
        AttributeHeader field;
        memcpy(&field, bytes, sizeof(field));
        const size_t aligned = (size_t(field.length) + 3) & ~size_t(3);
        if (field.length < sizeof(field) || aligned > length || (field.type & 0xc000) ||
            field.length - sizeof(field) > sizeof(IntelWifi::ScanSsid::bytes))
            return -22;

        const size_t size = field.length - sizeof(field);
        const auto* name = bytes + sizeof(field);
        unsigned i = 0;
        while (i < ssids.count &&
               (ssids.entries[i].length != size || memcmp(ssids.entries[i].bytes, name, size)))
            ++i;
        if (i == ssids.count) {
            auto& ssid = ssids.entries[ssids.count++];
            ssid.length = uint8_t(size);
            memcpy(ssid.bytes, name, size);
        }
        bytes += aligned;
        length -= aligned;
    }
    return 0;
}

int select(const uint8_t* bytes, size_t length, uint8_t command, bool dump, unsigned index,
           IntelWifi::ScanRequest& scan) {
    bool selected_phy = false, selected_device = false;
    bool frequencies_seen = false, ssids_seen = false;
    while (length) {
        if (length < sizeof(AttributeHeader))
            return -22;
        AttributeHeader field;
        memcpy(&field, bytes, sizeof(field));
        const size_t aligned = (size_t(field.length) + 3) & ~size_t(3);
        if (field.length < sizeof(field) || aligned > length)
            return -22;
        const auto* value = bytes + sizeof(field);
        const size_t size = field.length - sizeof(field);
        switch (field.type & 0x3fff) {
        case wiphy:
        case ifindex: {
            uint32_t id;
            if (size != sizeof(id))
                return -22;
            memcpy(&id, value, sizeof(id));
            const bool phy = (field.type & 0x3fff) == wiphy;
            if (id != (phy ? 0u : index))
                return -19;
            (phy ? selected_phy : selected_device) = true;
            break;
        }
        case wdev: {
            uint64_t id;
            if (size != sizeof(id))
                return -22;
            memcpy(&id, value, sizeof(id));
            if (id != device_id)
                return -19;
            selected_device = true;
            break;
        }
        case scan_flags:
            if (command == nl80211_trigger_scan) {
                uint32_t flags;
                if (size != sizeof(flags))
                    return -22;
                memcpy(&flags, value, sizeof(flags));
                // This radio has no 6 GHz channels. The colocated-AP hint does not affect its scan.
                if (flags & ~scan_colocated_6ghz)
                    return -95;
            }
            break;
        case scan_frequencies:
            if (command == nl80211_trigger_scan) {
                if (frequencies_seen)
                    return -22;
                if (const int error = select_frequencies(value, size, scan.channels))
                    return error;
                frequencies_seen = true;
            }
            break;
        case scan_ssids:
            if (command == nl80211_trigger_scan) {
                if (ssids_seen)
                    return -22;
                if (const int error = select_ssids(value, size, scan.ssids))
                    return error;
                ssids_seen = true;
            }
            break;
        default:
            if (command == nl80211_trigger_scan)
                return -95;
            break;
        }
        length -= aligned;
        bytes += aligned;
    }
    if (command == nl80211_get_wiphy)
        return dump || selected_device || selected_phy ? 0 : -22;
    return selected_device || (dump && command == nl80211_get_interface) ? 0 : -22;
}

void radio_band(Message& message, const IntelWifi::ScanChannelList& list, uint16_t band,
                bool live) {
    unsigned first = 0;
    const auto band_of = [](const IntelWifi::ScanChannel& channel) {
        return uint16_t(channel.frequency_mhz >= 5000);
    };
    while (first < list.count && band_of(list.entries[first]) != band)
        ++first;
    if (first == list.count)
        return;
    const size_t band_start = message.begin_nested(band);
    const size_t frequencies = message.begin_nested(band_frequencies);
    for (unsigned i = first; i < list.count && band_of(list.entries[i]) == band; ++i) {
        const auto& channel = list.entries[i];
        const size_t entry = message.begin_nested(uint16_t(i - first + 1));
        message.value(center_frequency, uint32_t(channel.frequency_mhz));
        if (!channel.allowed) {
            message.attr(frequency_disabled, nullptr, 0);
        } else {
            if (!live || !channel.active)
                message.attr(frequency_no_ir, nullptr, 0);
            if (channel.radar)
                message.attr(frequency_radar, nullptr, 0);
            if (channel.indoor)
                message.attr(frequency_indoor, nullptr, 0);
        }
        message.end_nested(entry);
    }
    message.end_nested(frequencies);

    using IntelWifi::scan_cck_rate_count;
    using IntelWifi::scan_legacy_rates;
    const size_t rates_start = message.begin_nested(band_rates);
    const unsigned first_rate = band ? scan_cck_rate_count : 0;
    for (unsigned i = first_rate; i < sizeof(scan_legacy_rates); ++i) {
        const size_t entry = message.begin_nested(uint16_t(i - first_rate + 1));
        message.value(rate_tenths_mbps, uint32_t(scan_legacy_rates[i]) * 5);
        if (i && i < scan_cck_rate_count)
            message.attr(rate_short_preamble, nullptr, 0);
        message.end_nested(entry);
    }
    message.end_nested(rates_start);
    message.end_nested(band_start);
}

size_t dump_done(void* output, uint32_t sequence, uint32_t port, bool interrupted = false) {
    const NetlinkHeader done{20, 3, uint16_t(multipart | (interrupted ? 0x10 : 0)), sequence, port};
    constexpr int status = 0;
    if (output) {
        memcpy(output, &done, sizeof(done));
        memcpy(static_cast<uint8_t*>(output) + sizeof(done), &status, sizeof(status));
    }
    return done.length;
}
} // namespace

bool wireless_scan_available() {
    return IntelWifi::passive_scan_snapshot() && IntelWifi::passive_scan_interface();
}

bool wireless_trigger_available() {
    return IntelWifi::live_scan_available();
}

bool wireless_connect_available() {
    return IntelWifi::live_connect_available();
}

size_t wireless_reply_capacity(const NetlinkHeader& header, const uint8_t* request) {
    return header.type == nl80211_family && header.length >= sizeof(header) + 4 &&
                   request[sizeof(header)] == nl80211_get_wiphy
               ? radio_reply_size
               : 0;
}

size_t wireless_reply(const void* data, const NetlinkHeader& request, uint32_t port, bool capped,
                      bool privileged, void* reply, void* followup, size_t& followup_length,
                      WirelessDump& cursor) {
    const auto* bytes = static_cast<const uint8_t*>(data);
    constexpr size_t header = sizeof(request) + 4;
    if (request.length < header)
        return netlink_ack(data, request, port, -22, capped, reply);
    const uint8_t command = bytes[sizeof(request)];
    const bool key_command = command == nl80211_new_key || command == nl80211_del_key;
    const auto* info = net_info(IntelWifi::passive_scan_interface());
    if (!info || !wireless_scan_available())
        return netlink_ack(data, request, port, -2, capped || key_command, reply);
    const bool dump = (request.flags & dump_flags) == dump_flags;
    if (key_command) {
        int error = dump ? -95 : privileged ? 0 : -1;
        KeyAttributes key;
        if (!error)
            error = select_key_request(bytes + header, request.length - header, info->index,
                                       command == nl80211_new_key, key);
        if (!error)
            error = IntelWifi::request_live_key(key.request);
        // An error ACK must never echo the key material.
        return error || (request.flags & 4) ? netlink_ack(data, request, port, error, true, reply)
                                            : 0;
    }
    const bool trigger = command == nl80211_trigger_scan;
    if (command == nl80211_connect || command == nl80211_disconnect ||
        command == nl80211_set_station) {
        if (dump || !wireless_connect_available())
            return netlink_ack(data, request, port, -95, capped, reply);
        if (!privileged)
            return netlink_ack(data, request, port, -1, capped, reply);
        StationAttributes station_request;
        int error = select_station_request(bytes + header, request.length - header, info->index,
                                           command, station_request);
        if (!error) {
            if (command == nl80211_connect &&
                station_request.connection.akm != IntelWifi::RsnAkm::open &&
                !IntelWifi::live_rsn_available())
                error = -95;
            else if (command == nl80211_connect)
                error = IntelWifi::request_live_connection(station_request.connection,
                                                           station_request.owned ? port : 0);
            else if (command == nl80211_disconnect)
                error = IntelWifi::request_live_disconnect(station_request.reason, port);
            else
                error = IntelWifi::authorize_live_station(station_request.connection.bssid,
                                                          station_request.authorized);
        }
        return error || (request.flags & 4) ? netlink_ack(data, request, port, error, capped, reply)
                                            : 0;
    }
    if ((command != nl80211_get_wiphy && command != nl80211_get_interface &&
         command != nl80211_get_scan && !trigger) ||
        (command == nl80211_get_scan && !dump) || (trigger && dump))
        return netlink_ack(data, request, port, -95, capped, reply);
    if (trigger && !privileged)
        return netlink_ack(data, request, port, -1, capped, reply);
    IntelWifi::ScanRequest scan;
    if (int error =
            select(bytes + header, request.length - header, command, dump, info->index, scan))
        return netlink_ack(data, request, port, error, capped, reply);
    if (command == nl80211_get_scan) {
        if (cursor.active)
            return netlink_ack(data, request, port, -16, capped, reply);
        cursor = {request.sequence, IntelWifi::passive_scan_generation(), 0, true};
        return 0;
    }
    if (trigger) {
        const int status = IntelWifi::trigger_live_scan(scan);
        if (status || (request.flags & 4))
            return netlink_ack(data, request, port, status, capped, reply);
        return 0;
    }

    if (dump)
        followup_length = dump_done(followup, request.sequence, port);
    else if (request.flags & 4)
        followup_length = netlink_ack(data, request, port, 0, capped, followup);
    Message message(reply);
    message.value(wiphy, uint32_t(0));
    message.value(generation, IntelWifi::passive_scan_generation());
    if (command == nl80211_get_wiphy) {
        message.value(wiphy_name, "phy0");
        const size_t types = message.begin_nested(supported_iftypes);
        message.attr(station, nullptr, 0);
        message.end_nested(types);
        const bool live = wireless_trigger_available();
        const bool rsn = IntelWifi::live_rsn_available();
        if (rsn) {
            message.value(cipher_suites, IntelWifi::ccmp_suite);
            const uint32_t suites[]{IntelWifi::enterprise_suite, IntelWifi::personal_suite};
            message.value(akm_suites, suites);
        }
        message.value(max_num_scan_ssids, uint8_t(live ? IntelWifi::scan_ssid_limit : 0));
        const size_t bands = message.begin_nested(wiphy_bands);
        const auto& list = IntelWifi::scan_channel_inventory();
        radio_band(message, list, 0, live);
        radio_band(message, list, 1, live);
        message.end_nested(bands);
        if (live || wireless_connect_available()) {
            const size_t commands = message.begin_nested(supported_commands);
            unsigned entry = 1;
            if (live)
                message.value(entry++, uint32_t(nl80211_trigger_scan));
            if (wireless_connect_available()) {
                message.value(entry++, uint32_t(nl80211_connect));
                message.value(entry++, uint32_t(nl80211_disconnect));
                message.value(entry++, uint32_t(nl80211_set_station));
                if (rsn) {
                    message.value(entry++, uint32_t(nl80211_new_key));
                    message.value(entry, uint32_t(nl80211_del_key));
                }
            }
            message.end_nested(commands);
        }
        return message.finish(new_wiphy, request.sequence, port, dump);
    }
    message.value(ifindex, uint32_t(info->index));
    message.attr(ifname, info->name, strlen(info->name) + 1);
    message.value(iftype, station);
    message.value(wdev, device_id);
    message.value(mac, info->mac);
    return message.finish(new_interface, request.sequence, port, dump);
}

size_t wireless_dump_record(const WirelessDump& cursor, uint32_t port, void* output) {
    if (cursor.generation != IntelWifi::passive_scan_generation())
        return dump_done(output, cursor.sequence, port, true);
    const auto& scan = *IntelWifi::passive_scan_snapshot();
    if (cursor.next >= scan.access_point_count)
        return dump_done(output, cursor.sequence, port);
    const auto& point = scan.access_points[cursor.next];
    const auto& elements = scan.elements->records[cursor.next];
    Message message(output);
    message.value(ifindex, uint32_t(IntelWifi::passive_scan_interface()));
    message.value(wdev, device_id);
    message.value(generation, cursor.generation);
    const size_t record = message.begin_nested(bss);
    message.value(bssid, point.bssid);
    message.value(frequency, uint32_t(point.frequency_mhz));
    message.value(beacon_interval, point.beacon_interval_tu);
    message.value(capability, point.capability);
    if (IntelWifi::live_bss_associated(point))
        message.value(bss_status, uint32_t(1)); // NL80211_BSS_STATUS_ASSOCIATED.
    if (point.signal_dbm != IntelWifi::scan_signal_unavailable)
        message.value(signal_mbm, int32_t(point.signal_dbm) * 100);
    if (point.probe_ie_bytes) {
        message.attr(probe_response_data, nullptr, 0);
        message.attr(information_elements, elements.probe, point.probe_ie_bytes);
    } else if (point.beacon_ie_bytes)
        message.attr(information_elements, elements.beacon, point.beacon_ie_bytes);
    if (point.beacon_ie_bytes)
        message.attr(beacon_elements, elements.beacon, point.beacon_ie_bytes);
    message.end_nested(record);
    return message.finish(new_scan_results, cursor.sequence, port, true);
}

void wireless_dump_advance(WirelessDump& cursor) {
    if (cursor.generation != IntelWifi::passive_scan_generation() ||
        cursor.next == IntelWifi::passive_scan_snapshot()->access_point_count)
        cursor.active = false;
    else
        ++cursor.next;
}

void wireless_scan_finished(unsigned index, bool complete) {
    uint8_t bytes[64];
    Message event(bytes);
    event.value(wiphy, uint32_t(0));
    event.value(ifindex, uint32_t(index));
    event.value(wdev, device_id);
    const size_t size = event.finish(complete ? new_scan_results : scan_aborted, 0, 0, false);
    netlink_broadcast_wireless(nl80211_scan_group, bytes, size);
}

void wireless_connection_finished(unsigned index, const uint8_t (&bssid)[6], uint16_t status,
                                  bool timeout, WirelessElements request,
                                  WirelessElements response) {
    uint8_t
        bytes[80 + IntelWifi::association_body_bytes + IntelWifi::association_response_ie_capacity];
    Message event(bytes);
    event.value(wiphy, uint32_t(0));
    event.value(ifindex, uint32_t(index));
    event.value(mac, bssid);
    event.value(status_code, status);
    if (request.length && request.length <= IntelWifi::association_body_bytes)
        event.attr(request_ies, request.bytes, request.length);
    if (response.length && response.length <= IntelWifi::association_response_ie_capacity)
        event.attr(response_ies, response.bytes, response.length);
    if (timeout)
        event.attr(timed_out, nullptr, 0);
    const size_t size = event.finish(nl80211_connect, 0, 0, false);
    netlink_broadcast_wireless(nl80211_mlme_group, bytes, size);
}

void wireless_disconnected(unsigned index, uint16_t reason, bool from_ap) {
    uint8_t bytes[64];
    Message event(bytes);
    event.value(wiphy, uint32_t(0));
    event.value(ifindex, uint32_t(index));
    if (reason)
        event.value(reason_code, reason);
    if (from_ap)
        event.attr(disconnected_by_ap, nullptr, 0);
    const size_t size = event.finish(nl80211_disconnect, 0, 0, false);
    netlink_broadcast_wireless(nl80211_mlme_group, bytes, size);
}

void wireless_socket_closed(unsigned port) {
    IntelWifi::close_connection_owner(port);
}
} // namespace ax
