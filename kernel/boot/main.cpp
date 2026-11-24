// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/boot/main.cpp
 * @brief   Starts the Axiom64 kernel and enters userspace.
 * @author  frankischilling
 * @date    2026-11-19
 *
 * Initializes memory, firmware, device drivers, and the root filesystem
 * before starting the first Ring 3 process.
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
#include "boot/boot.hpp"
#include "arch/x86_64/interrupts.hpp"
#include "boot/arguments.hpp"
#include "boot/root.hpp"
#include "drivers/block/block.hpp"
#include "drivers/net/intel_wifi.hpp"
#include "drivers/platform/devices.hpp"
#include "drivers/platform/inventory.hpp"
#include "drivers/platform/intel_lpss.hpp"
#include "drivers/platform/pci_inventory.hpp"
#include "drivers/platform/power_supply.hpp"
#include "drivers/usb/xhci.hpp"
#include "process/task.hpp"
#include "net/ethernet.hpp"
#include "net/netlink.hpp"
#include "core/time.hpp"
#include "core/random.hpp"
#include "firmware/acpi.hpp"
#include "fs/vfs.hpp"

namespace ax {
BootInfo boot_info;

[[noreturn]] void boot_kernel() {
    log("Axiom64 x86-64\n");
    log("Boot protocol: %s\n", boot_info.protocol);
    log("Firmware: %s\n", boot_info.firmware);
    BootArguments arguments(boot_info.command);
    test_mode = arguments.has("test");
    trace_syscalls = arguments.has("trace");
    if (arguments.has("suite=desktop"))
        test_suite = "AXIOM64_SUITE=desktop";
    else if (arguments.has("suite=abi"))
        test_suite = "AXIOM64_SUITE=abi";
    else if (arguments.has("suite=storage"))
        test_suite = "AXIOM64_SUITE=storage";
    else if (arguments.has("suite=ext2"))
        test_suite = "AXIOM64_SUITE=ext2";
    else if (arguments.has("suite=root"))
        test_suite = "AXIOM64_SUITE=root";
    else if (arguments.has("suite=threads"))
        test_suite = "AXIOM64_SUITE=threads";
    else if (arguments.has("suite=network"))
        test_suite = "AXIOM64_SUITE=network";
    if (arguments.has("phase=write"))
        test_phase = "AXIOM64_PHASE=write";
    else if (arguments.has("phase=verify"))
        test_phase = "AXIOM64_PHASE=verify";
    else if (arguments.has("phase=readonly"))
        test_phase = "AXIOM64_PHASE=readonly";
    else if (arguments.has("phase=error"))
        test_phase = "AXIOM64_PHASE=error";
    else if (arguments.has("phase=recovery"))
        test_phase = "AXIOM64_PHASE=recovery";
    else if (arguments.has("phase=queue"))
        test_phase = "AXIOM64_PHASE=queue";
    else if (arguments.has("phase=invalid"))
        test_phase = "AXIOM64_PHASE=invalid";
    else if (arguments.has("phase=full"))
        test_phase = "AXIOM64_PHASE=full";
    else if (arguments.has("phase=cache"))
        test_phase = "AXIOM64_PHASE=cache";
    else if (arguments.has("phase=cond"))
        test_phase = "AXIOM64_PHASE=cond";
    else if (arguments.has("phase=io"))
        test_phase = "AXIOM64_PHASE=io";
    else if (arguments.has("phase=pressure"))
        test_phase = "AXIOM64_PHASE=pressure";
    else if (arguments.has("phase=mapping-held"))
        test_phase = "AXIOM64_PHASE=mapping-held";
    memory_init();
    arch_init();
    uint64_t rsdp = boot_info.rsdp;
    Acpi::InterruptTopology topology;
    Acpi::DefinitionBlocks definitions;
    bool have_topology = firmware_discover(rsdp, topology, definitions);
    const bool schedule_peers = arguments.has("smp.scheduler");
    clock_init(rsdp, schedule_peers);
    const bool power_supply = arguments.has("acpi.power");
    if (power_supply)
        DeviceInventory::power_supply_prepare(definitions);
    if (schedule_peers && !clock_shared_counter_ready())
        log("SMP: scheduler requires a shared platform counter\n");
    if (schedule_peers || arguments.has("smp.probe"))
        boot_probe_application_processors(schedule_peers && clock_shared_counter_ready());
    if (arguments.has("irq=pic"))
        log("Interrupts: PIC/PIT selected by boot option\n");
    else if (have_topology)
        interrupt_init_apic(topology);
    else
        log("Interrupts: PIC/PIT fallback, no validated MADT\n");
    firmware_configure_pci_interrupts(rsdp, topology, definitions);
    const bool lpss_bar_test = arguments.has("lpss.i2c.bar-test");
    const bool lpss_hid_test = arguments.has("lpss.i2c.hid-test");
    if (lpss_hid_test || lpss_bar_test || arguments.has("lpss.i2c.probe")) {
        const auto mode = lpss_hid_test   ? LpssProbe::hid
                          : lpss_bar_test ? LpssProbe::bar
                                          : LpssProbe::inspect;
        intel_lpss_i2c_probe(definitions, have_topology ? &topology : nullptr, mode);
    }
    if (arguments.has("hid.i2c.probe"))
        firmware_probe_i2c_hid(definitions);
    random_init(!arguments.has("random.trust_cpu=off"), arguments.has("random.trust_virtio=on"));
    if (!boot_info.initramfs || !boot_info.initramfs_size)
        panic("missing or empty root filesystem module");
    log("Boot modules: count=%u initramfs_bytes=%u\n", boot_info.module_count,
        boot_info.initramfs_size);
    char init[sizeof(Path::text)] = "/sbin/init";
    if (arguments.read("init=", init, sizeof(init)) < 0 || init[0] != '/') {
        log("BOOT_INIT_FAIL stage=configuration errno=22\n");
        poweroff(1);
    }
    vfs_init(boot_info.initramfs, boot_info.initramfs_size);
    auto wifi_firmware = arguments.has("iwlwifi.boot-firmware") && !arguments.has("iwlwifi.disable")
                             ? IntelWifi::read_boot_firmware()
                             : IntelWifi::BootFirmware{};
    block_init();
    boot_root_init(arguments, init);
    const bool usb_keyboard_probe = arguments.has("usb.xhci=keyboard-probe");
    const bool usb_keyboard = arguments.has("usb.xhci=keyboard");
    if (!usb_keyboard && (usb_keyboard_probe || arguments.has("usb.xhci=probe")))
        xhci_probe(usb_keyboard_probe);
    devices_init(arguments.has("fbconsole"), arguments.has("virtio.gpu=2d"),
                 arguments.has("drm.scanout"));
    if (usb_keyboard)
        xhci_keyboard_init();
    if (arguments.has("lpss.i2c.input"))
        intel_lpss_i2c_probe(definitions, have_topology ? &topology : nullptr, LpssProbe::input);
    if (arguments.has("acpi.power.probe") && !power_supply)
        firmware_probe_power_supplies(definitions);
    if (power_supply)
        DeviceInventory::power_supply_init();
    publish_pci_inventory();
    DeviceInventory::network_inventory_init();
    net_init(DeviceInventory::publish_ethernet);
    net_observe_links(netlink_link_event);
    ipv4_observe_addresses(netlink_ipv4_address_event);
    ipv4_observe_routes(netlink_ipv4_route_event);
    ipv6_observe_addresses(netlink_ipv6_address_event);
    const bool probe_wifi = arguments.has("iwlwifi.probe");
    auto wifi_check = IntelWifi::FirmwareCheck::stage;
    IntelWifi::AuthenticationTarget auth_target;
    char auth_bssid[18]{};
    char assoc_bssid[18]{};
    char data_target[50]{};
    char open_bssid[18]{};
    const int auth_argument = arguments.read("iwlwifi.auth-check=", auth_bssid, sizeof(auth_bssid));
    const int assoc_argument =
        arguments.read("iwlwifi.assoc-check=", assoc_bssid, sizeof(assoc_bssid));
    const int data_argument =
        arguments.read("iwlwifi.data-check=", data_target, sizeof(data_target));
    const int open_argument = arguments.read("iwlwifi.open-link=", open_bssid, sizeof(open_bssid));
    const bool wants_auth = auth_argument || arguments.has("iwlwifi.auth-check");
    const bool wants_assoc = assoc_argument || arguments.has("iwlwifi.assoc-check");
    const bool wants_data = data_argument || arguments.has("iwlwifi.data-check");
    const bool wants_open = open_argument || arguments.has("iwlwifi.open-link");
    const char* wifi_check_error = nullptr;
    if (wants_auth + wants_assoc + wants_data + wants_open > 1) {
        wifi_check_error = wants_data || wants_open
                               ? "iwlwifi: select only one wireless exchange check\n"
                               : "iwlwifi: select either auth-check or assoc-check\n";
    } else if (wants_open) {
        wifi_check = IntelWifi::FirmwareCheck::open_link;
        if (open_argument != 1 || !IntelWifi::parse_authentication_target(open_bssid, auth_target))
            wifi_check_error = "iwlwifi: open-link requires one unicast BSSID\n";
    } else if (wants_data) {
        wifi_check = IntelWifi::FirmwareCheck::data_probe;
        if (data_argument != 1 || !IntelWifi::parse_data_probe_target(data_target, auth_target))
            wifi_check_error = "iwlwifi: data-check requires BSSID,source IPv4,peer IPv4\n";
    } else if (wants_assoc) {
        wifi_check = IntelWifi::FirmwareCheck::associate;
        if (assoc_argument != 1 ||
            !IntelWifi::parse_authentication_target(assoc_bssid, auth_target))
            wifi_check_error = "iwlwifi: assoc-check requires one unicast BSSID\n";
    } else if (wants_auth) {
        wifi_check = IntelWifi::FirmwareCheck::authenticate;
        if (auth_argument != 1 || !IntelWifi::parse_authentication_target(auth_bssid, auth_target))
            wifi_check_error = "iwlwifi: auth-check requires one unicast BSSID\n";
    } else if (arguments.has("iwlwifi.live-scan"))
        wifi_check = IntelWifi::FirmwareCheck::live_scan;
    else if (arguments.has("iwlwifi.peer-queue-check"))
        wifi_check = IntelWifi::FirmwareCheck::peer_queue;
    else if (arguments.has("iwlwifi.channel-check"))
        wifi_check = IntelWifi::FirmwareCheck::channel_context;
    else if (arguments.has("iwlwifi.key-check"))
        wifi_check = IntelWifi::FirmwareCheck::security_key;
    else if (arguments.has("iwlwifi.rescan-check"))
        wifi_check = IntelWifi::FirmwareCheck::rescan;
    else if (arguments.has("iwlwifi.passive-scan"))
        wifi_check = IntelWifi::FirmwareCheck::passive_scan;
    else if (arguments.has("iwlwifi.regulatory-check"))
        wifi_check = IntelWifi::FirmwareCheck::regulatory;
    else if (arguments.has("iwlwifi.scan-config-check"))
        wifi_check = IntelWifi::FirmwareCheck::scan_config;
    else if (arguments.has("iwlwifi.nvm-check"))
        wifi_check = IntelWifi::FirmwareCheck::nvm;
    else if (arguments.has("iwlwifi.start-check"))
        wifi_check = IntelWifi::FirmwareCheck::start;
    if (arguments.has("iwlwifi.disable"))
        log("iwlwifi: disabled by boot option\n");
    else if (wifi_check_error)
        log(wifi_check_error);
    else if (probe_wifi || wifi_check != IntelWifi::FirmwareCheck::stage ||
             arguments.has("iwlwifi.firmware-check"))
        IntelWifi::check_firmware(probe_wifi, wifi_check, auth_target, &wifi_firmware);
    else if (wifi_firmware.bytes)
        IntelWifi::check_firmware(false, IntelWifi::FirmwareCheck::live_scan, {}, &wifi_firmware);
    else
        IntelWifi::start_if_available();
    release(wifi_firmware.bytes);
    log("Entering userspace in Ring 3\n");
    start_init(init, arguments.has("debug.ssh"), arguments.has("console.text"));
    __builtin_unreachable();
}
} // namespace ax
