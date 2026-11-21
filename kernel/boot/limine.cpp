// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/boot/limine.cpp
 * @brief   Translate the Limine boot responses.
 * @author  frankischilling
 * @date    2026-11-21
 *
 * Preserves the bootloader memory map, module, and framebuffer handoff.
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
#include "drivers/platform/legacy_io.hpp"
#include "limine.h"

namespace ax {
[[gnu::used, gnu::section(".limine_requests_start")]] static volatile uint64_t requests_start[] =
    LIMINE_REQUESTS_START_MARKER;
[[gnu::used, gnu::section(".limine_requests")]] static volatile uint64_t base_revision[] =
    LIMINE_BASE_REVISION(3);
[[gnu::used, gnu::section(".limine_requests")]] static volatile limine_hhdm_request hhdm_request = {
    LIMINE_HHDM_REQUEST_ID, 0, nullptr};
[[gnu::used,
  gnu::section(".limine_requests")]] static volatile limine_memmap_request memmap_request = {
    LIMINE_MEMMAP_REQUEST_ID, 0, nullptr};
[[gnu::used,
  gnu::section(".limine_requests")]] static volatile limine_module_request module_request = {
    LIMINE_MODULE_REQUEST_ID, 0, nullptr, 0, nullptr};
[[gnu::used, gnu::section(".limine_requests")]] static volatile limine_framebuffer_request
    framebuffer_request = {LIMINE_FRAMEBUFFER_REQUEST_ID, 0, nullptr};
[[gnu::used, gnu::section(".limine_requests")]] static volatile limine_executable_cmdline_request
    cmdline_request = {LIMINE_EXECUTABLE_CMDLINE_REQUEST_ID, 0, nullptr};
[[gnu::used, gnu::section(".limine_requests")]] static volatile limine_firmware_type_request
    firmware_request = {LIMINE_FIRMWARE_TYPE_REQUEST_ID, 0, nullptr};
[[gnu::used, gnu::section(".limine_requests")]] static volatile limine_rsdp_request rsdp_request = {
    LIMINE_RSDP_REQUEST_ID, 0, nullptr};
[[gnu::used, gnu::section(".limine_requests_end")]] static volatile uint64_t requests_end[] =
    LIMINE_REQUESTS_END_MARKER;

static BootMemory limine_memory(const void* context, size_t index) {
    auto& entry = *static_cast<const limine_memmap_response*>(context)->entries[index];
    BootMemoryKind kind;
    switch (entry.type) {
    case LIMINE_MEMMAP_USABLE:
        kind = BootMemoryKind::usable;
        break;
    case LIMINE_MEMMAP_RESERVED:
        kind = BootMemoryKind::reserved;
        break;
    case LIMINE_MEMMAP_ACPI_RECLAIMABLE:
    case LIMINE_MEMMAP_ACPI_NVS:
        kind = BootMemoryKind::firmware;
        break;
    case LIMINE_MEMMAP_BOOTLOADER_RECLAIMABLE:
        kind = BootMemoryKind::retained;
        break;
    case LIMINE_MEMMAP_RESERVED_MAPPED:
        kind = BootMemoryKind::mapped_reserved;
        break;
    default:
        kind = BootMemoryKind::other;
        break;
    }
    return {entry.base, entry.length, kind};
}

extern "C" [[noreturn]] void kernel_main() {
    asm volatile("cli; cld");
    serial_init();
    if (!LIMINE_BASE_REVISION_SUPPORTED(base_revision))
        panic("unsupported boot protocol");
    const auto* firmware = firmware_request.response;
    const char* firmware_name = "unknown";
    if (firmware && firmware->firmware_type == LIMINE_FIRMWARE_TYPE_X86BIOS)
        firmware_name = "BIOS";
    if (firmware && firmware->firmware_type == LIMINE_FIRMWARE_TYPE_EFI64)
        firmware_name = "UEFI";
    const auto* modules = module_request.response;
    const auto* module =
        modules && modules->module_count && modules->modules ? modules->modules[0] : nullptr;
    const auto* map = memmap_request.response;
    boot_info = {
        .protocol = "Limine",
        .firmware = firmware_name,
        .command = cmdline_request.response ? cmdline_request.response->cmdline : nullptr,
        .direct_offset = hhdm_request.response ? hhdm_request.response->offset : 0,
        .rsdp = rsdp_request.response ? uint64_t(rsdp_request.response->address) : 0,
        .memory_context = map,
        .memory_count = map && map->entries ? map->entry_count : 0,
        .memory_at = limine_memory,
        .initramfs = module ? module->address : nullptr,
        .initramfs_size = module ? module->size : 0,
        .module_count = modules ? modules->module_count : 0,
        .framebuffer = {},
    };
    const auto* response = framebuffer_request.response;
    if (response && response->framebuffer_count && response->framebuffers &&
        response->framebuffers[0]) {
        const auto& fb = *response->framebuffers[0];
        boot_info.framebuffer = {fb.address,
                                 fb.width,
                                 fb.height,
                                 fb.pitch,
                                 fb.bpp,
                                 fb.red_mask_size,
                                 fb.red_mask_shift,
                                 fb.green_mask_size,
                                 fb.green_mask_shift,
                                 fb.blue_mask_size,
                                 fb.blue_mask_shift};
    }
    boot_kernel();
}
} // namespace ax
