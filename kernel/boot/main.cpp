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
#include "drivers/platform/devices.hpp"
#include "drivers/platform/pci_inventory.hpp"
#include "drivers/usb/xhci.hpp"
#include "process/task.hpp"
#include "net/ethernet.hpp"
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
    block_init();
    boot_root_init(arguments, init);
    const bool usb_keyboard_probe = arguments.has("usb.xhci=keyboard-probe");
    const bool usb_keyboard = arguments.has("usb.xhci=keyboard");
    if (!usb_keyboard && (usb_keyboard_probe || arguments.has("usb.xhci=probe")))
        xhci_probe(usb_keyboard_probe);
    devices_init(arguments.has("fbconsole"), arguments.has("virtio.gpu=2d"));
    if (usb_keyboard)
        xhci_keyboard_init();
    net_init();
    publish_pci_inventory();
    log("Entering userspace in Ring 3\n");
    start_init(init, arguments.has("debug.ssh"), arguments.has("console.text"));
    __builtin_unreachable();
}
} // namespace ax
