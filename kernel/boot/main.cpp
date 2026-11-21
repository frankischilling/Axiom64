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
#include "process/task.hpp"
#include "net/ethernet.hpp"
#include "core/time.hpp"
#include "core/random.hpp"
#include "firmware/acpi.hpp"
#include "fs/vfs.hpp"

namespace ax {
[[gnu::used, gnu::section(".limine_requests_start")]] static volatile uint64_t requests_start[] =
    LIMINE_REQUESTS_START_MARKER;
[[gnu::used, gnu::section(".limine_requests")]] static volatile uint64_t base_revision[] =
    LIMINE_BASE_REVISION(3);
[[gnu::used, gnu::section(".limine_requests")]] volatile limine_hhdm_request hhdm_request = {
    LIMINE_HHDM_REQUEST_ID, 0, nullptr};
[[gnu::used, gnu::section(".limine_requests")]] volatile limine_memmap_request memmap_request = {
    LIMINE_MEMMAP_REQUEST_ID, 0, nullptr};
[[gnu::used, gnu::section(".limine_requests")]] volatile limine_module_request module_request = {
    LIMINE_MODULE_REQUEST_ID, 0, nullptr, 0, nullptr};
[[gnu::used,
  gnu::section(".limine_requests")]] volatile limine_framebuffer_request framebuffer_request = {
    LIMINE_FRAMEBUFFER_REQUEST_ID, 0, nullptr};
[[gnu::used,
  gnu::section(".limine_requests")]] volatile limine_executable_cmdline_request cmdline_request = {
    LIMINE_EXECUTABLE_CMDLINE_REQUEST_ID, 0, nullptr};
[[gnu::used, gnu::section(".limine_requests")]] static volatile limine_firmware_type_request
    firmware_request = {LIMINE_FIRMWARE_TYPE_REQUEST_ID, 0, nullptr};
[[gnu::used, gnu::section(".limine_requests")]] static volatile limine_rsdp_request rsdp_request = {
    LIMINE_RSDP_REQUEST_ID, 0, nullptr};
[[gnu::used, gnu::section(".limine_requests_end")]] static volatile uint64_t requests_end[] =
    LIMINE_REQUESTS_END_MARKER;

extern "C" [[noreturn]] void kernel_main() {
    asm volatile("cli");
    serial_init();
    log("Axiom64 x86-64\n");
    if (!LIMINE_BASE_REVISION_SUPPORTED(base_revision))
        panic("unsupported boot protocol");
    auto firmware = firmware_request.response;
    const char* firmware_name = "unknown";
    if (firmware && firmware->firmware_type == LIMINE_FIRMWARE_TYPE_X86BIOS)
        firmware_name = "BIOS";
    if (firmware && firmware->firmware_type == LIMINE_FIRMWARE_TYPE_EFI64)
        firmware_name = "UEFI";
    log("Firmware: %s\n", firmware_name);
    BootArguments arguments(cmdline_request.response ? cmdline_request.response->cmdline : nullptr);
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
    uint64_t rsdp = rsdp_request.response ? uint64_t(rsdp_request.response->address) : 0;
    Acpi::InterruptTopology topology;
    Acpi::DefinitionBlocks definitions;
    bool have_topology = firmware_discover(rsdp, topology, definitions);
    clock_init(rsdp);
    if (arguments.has("irq=pic"))
        log("Interrupts: PIC/PIT selected by boot option\n");
    else if (have_topology)
        interrupt_init_apic(topology);
    else
        log("Interrupts: PIC/PIT fallback, no validated MADT\n");
    firmware_configure_pci_interrupts(rsdp, topology, definitions);
    random_init(!arguments.has("random.trust_cpu=off"), arguments.has("random.trust_virtio=on"));
    auto modules = module_request.response;
    if (!modules || !modules->module_count || !modules->modules || !modules->modules[0])
        panic("missing root filesystem");
    const auto* initramfs = modules->modules[0];
    if (!initramfs->address || !initramfs->size)
        panic("empty root filesystem module");
    log("Boot modules: count=%u initramfs_bytes=%u\n", modules->module_count, initramfs->size);
    char init[sizeof(Path::text)] = "/sbin/init";
    if (arguments.read("init=", init, sizeof(init)) < 0 || init[0] != '/') {
        log("BOOT_INIT_FAIL stage=configuration errno=22\n");
        poweroff(1);
    }
    vfs_init(initramfs->address, initramfs->size);
    block_init();
    boot_root_init(arguments, init);
    devices_init();
    net_init();
    log("Entering userspace in Ring 3\n");
    start_init(init);
    __builtin_unreachable();
}
} // namespace ax
