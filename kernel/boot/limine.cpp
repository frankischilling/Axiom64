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
#include "arch/x86_64/cpu_local.hpp"
#include "arch/x86_64/interrupts.hpp"
#include "arch/x86_64/tlb.hpp"
#include "boot/boot.hpp"
#include "drivers/platform/legacy_io.hpp"
#include "drivers/platform/poll.hpp"
#include "limine.h"

namespace ax {
extern "C" [[noreturn]] void ap_enter_stack(uint64_t stack_top, void* state);
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
[[gnu::used, gnu::section(".limine_requests")]] static volatile limine_mp_request mp_request = {
    LIMINE_MP_REQUEST_ID, 0, nullptr, LIMINE_MP_REQUEST_X86_64_X2APIC};
[[gnu::used, gnu::section(".limine_requests_end")]] static volatile uint64_t requests_end[] =
    LIMINE_REQUESTS_END_MARKER;

namespace {
constexpr unsigned ap_timeout_ticks = 200;
constexpr unsigned ap_stack_pages = 4, ap_fault_pages = 2;
constexpr unsigned ap_wakeups = 2, ap_wakeup_timeout_ticks = 20;
constexpr unsigned ap_timer_firings = 2, ap_timer_timeout_ticks = 50;
constexpr uint32_t ap_timer_count = 32768;
constexpr unsigned ap_tlb_timeout_ticks = 50;
constexpr uint64_t probe_address = 0x400000;
constexpr uint64_t probe_first = 0x194c0716, probe_second = 0x73fe2909;

struct ApplicationProcessor {
    uint64_t stack = 0;
    unsigned slot = 0;
    uint32_t expected_apic_id = 0;
    uint32_t observed_apic_id = 0;
    bool entered = false;
    bool local_tables = false;
    bool wakeup_ready = false;
    bool wakeups_verified = false; // Written and read by the boot CPU only.
    unsigned wakeups = 0;
    unsigned timer_firings = 0;
    bool task_slot_idle = false;
    bool timer_checked = false;
    uint64_t tlb_before = 0;
    uint64_t tlb_after = 0;
    bool tlb_left = false;
};

ApplicationProcessor application_processors[max_boot_processors];
AddressSpace tlb_space;
uint64_t* tlb_leaf;
uint64_t tlb_original, tlb_replacement;
bool tlb_finished;

void release_tlb_probe() {
    if (tlb_leaf) {
        *tlb_leaf = 0;
        tlb_leaf = nullptr;
    }
    tlb_space.destroy();
    if (tlb_original) {
        page_free(tlb_original);
        tlb_original = 0;
    }
    if (tlb_replacement) {
        page_free(tlb_replacement);
        tlb_replacement = 0;
    }
}

bool prepare_tlb_probe() {
    if (!tlb_space.create())
        return false;
    tlb_leaf = tlb_space.entry(probe_address, true);
    tlb_original = page_alloc();
    tlb_replacement = page_alloc();
    if (!tlb_leaf || !tlb_original || !tlb_replacement) {
        release_tlb_probe();
        return false;
    }
    *static_cast<uint64_t*>(physical(tlb_original)) = probe_first;
    *static_cast<uint64_t*>(physical(tlb_replacement)) = probe_second;
    // A read-only supervisor mapping keeps the scratch page outside userspace.
    *tlb_leaf = tlb_original | 1;
    return true;
}

void record_secondary_event(uint32_t apic_id, Irq::SecondaryEvent event) {
    for (auto& state : application_processors)
        if (state.stack && state.expected_apic_id == apic_id) {
            auto& counter =
                event == Irq::SecondaryEvent::wake ? state.wakeups : state.timer_firings;
            __atomic_fetch_add(&counter, 1, __ATOMIC_RELEASE);
            return;
        }
}

unsigned probe_wakeups(const ApplicationProcessor& state) {
    for (unsigned count = 1; count <= ap_wakeups; ++count) {
        if (!interrupt_send_ipi(state.expected_apic_id) ||
            !DevicePoll::wait(
                [&] { return __atomic_load_n(&state.wakeups, __ATOMIC_ACQUIRE) >= count; },
                ap_wakeup_timeout_ticks))
            break;
    }
    return __atomic_load_n(&state.wakeups, __ATOMIC_ACQUIRE);
}

void probe_local_timer(ApplicationProcessor& state) {
    for (unsigned firing = 0; firing < ap_timer_firings; ++firing) {
        interrupt_arm_secondary_timer(ap_timer_count);
        while (__atomic_load_n(&state.timer_firings, __ATOMIC_RELAXED) == firing)
            asm volatile("sti; hlt; cli" ::: "memory");
    }
    interrupt_stop_secondary_timer();
    state.task_slot_idle = arch_secondary_task_slot_idle(state.slot);
    __atomic_store_n(&state.timer_checked, true, __ATOMIC_RELEASE);
}

void probe_tlb_on_secondary(ApplicationProcessor& state) {
    switch_address_space(tlb_space.root);
    const auto page = reinterpret_cast<const volatile uint64_t*>(probe_address);
    __atomic_store_n(&state.tlb_before, *page, __ATOMIC_RELEASE);
    while (!__atomic_load_n(&tlb_finished, __ATOMIC_ACQUIRE))
        asm volatile("sti; hlt; cli" ::: "memory");
    state.tlb_after = *page;
    activate_kernel_memory();
}

void check_tlb_probe() {
    if (!tlb_space.root)
        return;
    const bool warmed = DevicePoll::wait(
        [] {
            for (const auto& state : application_processors)
                if (state.stack &&
                    __atomic_load_n(&state.tlb_before, __ATOMIC_ACQUIRE) != probe_first)
                    return false;
            return true;
        },
        ap_tlb_timeout_ticks);
    bool invalidated = false;
    unsigned unrelated = 0, targets = 0, participants = 0;
    for (const auto& state : application_processors)
        participants += state.stack != 0;
    // The secondary CPUs switched away from the kernel root.
    if (warmed &&
        invalidate_user_translations(kernel_memory_root(), all_user_translations, &unrelated) &&
        !unrelated) {
        __atomic_store_n(tlb_leaf, tlb_replacement | 1, __ATOMIC_RELEASE);
        invalidated =
            invalidate_user_translations(tlb_space.root, all_user_translations, &targets) &&
            targets == participants;
    }
    log("SMP: translation targets=%u other=%u\n", uint64_t(targets), uint64_t(unrelated));
    if (!invalidated)
        log("SMP: remote page invalidation incomplete\n");
    __atomic_store_n(&tlb_finished, true, __ATOMIC_RELEASE);
    for (const auto& state : application_processors)
        if (state.stack && __atomic_load_n(&state.entered, __ATOMIC_ACQUIRE) &&
            state.wakeup_ready && !interrupt_send_ipi(state.expected_apic_id))
            break;
    const bool retired = DevicePoll::wait(
        [] {
            for (const auto& state : application_processors)
                if (state.stack && !__atomic_load_n(&state.tlb_left, __ATOMIC_ACQUIRE))
                    return false;
            return true;
        },
        ap_tlb_timeout_ticks);
    if (invalidated)
        for (const auto& state : application_processors) {
            if (!state.stack || !__atomic_load_n(&state.tlb_left, __ATOMIC_ACQUIRE))
                continue;
            if (state.tlb_after == probe_second)
                log("SMP: application processor apic=%u remote page invalidation verified\n",
                    uint64_t(state.expected_apic_id));
            else
                log("SMP: application processor apic=%u remote page invalidation read=%x\n",
                    uint64_t(state.expected_apic_id), state.tlb_after);
        }
    if (retired)
        release_tlb_probe();
    else
        log("SMP: retained probe pages while a secondary CPU may still use them\n");
}

[[noreturn]] void application_processor_entry(limine_mp_info* processor) {
    asm volatile("cli; cld" ::: "memory");
    auto state = reinterpret_cast<ApplicationProcessor*>(processor->extra_argument);
    const auto stack_top = uint64_t(physical(state->stack + ap_stack_pages * page_size));
    ap_enter_stack(stack_top, state);
}
} // namespace

extern "C" [[noreturn]] void ap_entry_on_stack(void* argument) {
    auto state = static_cast<ApplicationProcessor*>(argument);
    write_cr3(kernel_memory_root());
    const auto stack_bottom = uint64_t(physical(state->stack));
    const auto stack_top = stack_bottom + ap_stack_pages * page_size;
    const auto fault_top = stack_top + ap_fault_pages * page_size;
    uint64_t current_stack;
    asm volatile("mov %%rsp,%0" : "=r"(current_stack));
    state->observed_apic_id = arch_current_apic_id();
    state->local_tables = current_stack >= stack_bottom && current_stack < stack_top &&
                          arch_init_secondary_tables(state->slot, stack_top, fault_top);
    if (state->local_tables)
        register_tlb_cpu(state->observed_apic_id);
    state->wakeup_ready = state->local_tables &&
                          state->observed_apic_id == state->expected_apic_id &&
                          interrupt_enable_secondary_ipi();
    __atomic_store_n(&state->entered, true, __ATOMIC_RELEASE);
    if (state->wakeup_ready) {
        while (__atomic_load_n(&state->wakeups, __ATOMIC_ACQUIRE) < ap_wakeups)
            asm volatile("sti; hlt; cli" ::: "memory");
        probe_local_timer(*state);
        if (tlb_space.root)
            probe_tlb_on_secondary(*state);
    }
    if (state->local_tables)
        unregister_tlb_cpu();
    __atomic_store_n(&state->tlb_left, true, __ATOMIC_RELEASE);
    // Device interrupts and the scheduler still belong to the BSP.
    for (;;)
        asm volatile("hlt");
}

void boot_probe_application_processors() {
    const auto response = mp_request.response;
    if (!response || !response->cpus || !response->cpu_count ||
        response->cpu_count > max_boot_processors) {
        log("SMP: boot protocol processor list unavailable\n");
        return;
    }
    unsigned bootstrap = 0;
    for (unsigned i = 0; i < response->cpu_count; ++i) {
        const auto cpu = response->cpus[i];
        if (!cpu || cpu->goto_address) {
            log("SMP: invalid boot processor entry\n");
            return;
        }
        if (cpu->lapic_id == response->bsp_lapic_id)
            ++bootstrap;
        for (unsigned j = 0; j < i; ++j) {
            if (cpu->lapic_id == response->cpus[j]->lapic_id) {
                log("SMP: duplicate boot processor ID\n");
                return;
            }
        }
    }
    if (bootstrap != 1 || arch_current_apic_id() != response->bsp_lapic_id) {
        log("SMP: bootstrap processor ID mismatch\n");
        return;
    }
    constexpr unsigned stack_pages = ap_stack_pages + ap_fault_pages;
    for (unsigned i = 0; i < response->cpu_count; ++i) {
        if (response->cpus[i]->lapic_id == response->bsp_lapic_id)
            continue;
        const auto stack = page_alloc(stack_pages);
        if (!stack) {
            for (unsigned prior = 0; prior < i; ++prior)
                if (application_processors[prior].stack) {
                    page_free(application_processors[prior].stack, stack_pages);
                    application_processors[prior] = {};
                }
            log("SMP: application processor stack allocation failed\n");
            return;
        }
        application_processors[i] = {
            .stack = stack, .slot = i, .expected_apic_id = response->cpus[i]->lapic_id};
    }
    if (response->cpu_count > 1) {
        if (!interrupt_prepare_secondary(record_secondary_event))
            log("SMP: IPI transport unavailable\n");
        else if (!prepare_tlb_probe())
            log("SMP: remote page invalidation probe allocation failed\n");
    }
    for (unsigned i = 0; i < response->cpu_count; ++i) {
        auto cpu = response->cpus[i];
        if (cpu->lapic_id == response->bsp_lapic_id)
            continue;
        cpu->extra_argument = uint64_t(&application_processors[i]);
        __atomic_store_n(&cpu->goto_address, &application_processor_entry, __ATOMIC_RELEASE);
    }
    DevicePoll::wait(
        [&] {
            for (unsigned i = 0; i < response->cpu_count; ++i) {
                if (response->cpus[i]->lapic_id != response->bsp_lapic_id &&
                    !__atomic_load_n(&application_processors[i].entered, __ATOMIC_ACQUIRE))
                    return false;
            }
            return true;
        },
        ap_timeout_ticks);

    unsigned started = 0;
    for (unsigned i = 0; i < response->cpu_count; ++i) {
        const auto cpu = response->cpus[i];
        auto& state = application_processors[i];
        if (cpu->lapic_id == response->bsp_lapic_id)
            continue;
        if (!__atomic_load_n(&state.entered, __ATOMIC_ACQUIRE)) {
            log("SMP: processor apic=%u did not enter\n", uint64_t(cpu->lapic_id));
        } else if (state.observed_apic_id != cpu->lapic_id) {
            log("SMP: processor apic=%u observed=%u mismatch\n", uint64_t(cpu->lapic_id),
                uint64_t(state.observed_apic_id));
        } else if (!state.local_tables) {
            log("SMP: processor apic=%u local tables unavailable\n", uint64_t(cpu->lapic_id));
        } else {
            ++started;
            log("SMP: application processor apic=%u entered\n", uint64_t(cpu->lapic_id));
            log("SMP: application processor apic=%u stack, TSS, IDT and syscall entry ready\n",
                uint64_t(cpu->lapic_id));
            const unsigned wakeups = state.wakeup_ready ? probe_wakeups(state) : 0;
            log("SMP: application processor apic=%u wake interrupts=%u\n", uint64_t(cpu->lapic_id),
                uint64_t(wakeups));
            state.wakeups_verified = wakeups == ap_wakeups;
        }
    }
    DevicePoll::wait(
        [&] {
            for (const auto& state : application_processors)
                if (state.wakeups_verified &&
                    !__atomic_load_n(&state.timer_checked, __ATOMIC_ACQUIRE))
                    return false;
            return true;
        },
        ap_timer_timeout_ticks);
    for (const auto& state : application_processors) {
        if (!state.wakeups_verified)
            continue;
        const bool checked = __atomic_load_n(&state.timer_checked, __ATOMIC_ACQUIRE);
        const unsigned firings = checked ? state.timer_firings : 0;
        log("SMP: application processor apic=%u local timer interrupts=%u\n",
            uint64_t(state.expected_apic_id), uint64_t(firings));
        if (checked && state.task_slot_idle)
            log("SMP: application processor apic=%u idle task slot ready\n",
                uint64_t(state.expected_apic_id));
    }
    check_tlb_probe();
    log("SMP: present=%u bsp=%u application_processors=%u\n", response->cpu_count,
        uint64_t(response->bsp_lapic_id), uint64_t(started));
}

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
        kind = BootMemoryKind::firmware;
        break;
    case LIMINE_MEMMAP_ACPI_NVS:
        kind = BootMemoryKind::acpi_nvs;
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
