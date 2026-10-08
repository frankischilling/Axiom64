// SPDX-License-Identifier: GPL-3.0-or-later
#include "boot/boot.hpp"
#include "boot/root.hpp"
#include "drivers/block/block.hpp"
#include "drivers/platform/devices.hpp"
#include "process/task.hpp"
#include "net/ethernet.hpp"

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
[[gnu::used, gnu::section(".limine_requests_end")]] static volatile uint64_t requests_end[] =
    LIMINE_REQUESTS_END_MARKER;

static bool word(const char* s, const char* match) {
    size_t len = strlen(match);
    for (size_t i = 0; s[i]; i++)
        if ((i == 0 || s[i - 1] == ' ') && !memcmp(s + i, match, len) &&
            (!s[i + len] || s[i + len] == ' '))
            return true;
    return false;
}

extern "C" [[noreturn]] void kernel_main() {
    asm volatile("cli");
    serial_init();
    log("Axiom64 x86-64\n");
    if (!LIMINE_BASE_REVISION_SUPPORTED(base_revision))
        panic("unsupported boot protocol");
    auto firmware = firmware_request.response;
    log("Firmware: %s\n",
        firmware && firmware->firmware_type == LIMINE_FIRMWARE_TYPE_EFI64 ? "UEFI" : "BIOS");
    const char* cmd = cmdline_request.response ? cmdline_request.response->cmdline : "";
    test_mode = word(cmd, "test");
    trace_syscalls = word(cmd, "trace");
    if (word(cmd, "suite=desktop"))
        test_suite = "AXIOM64_SUITE=desktop";
    else if (word(cmd, "suite=abi"))
        test_suite = "AXIOM64_SUITE=abi";
    else if (word(cmd, "suite=storage"))
        test_suite = "AXIOM64_SUITE=storage";
    else if (word(cmd, "suite=ext2"))
        test_suite = "AXIOM64_SUITE=ext2";
    else if (word(cmd, "suite=root"))
        test_suite = "AXIOM64_SUITE=root";
    else if (word(cmd, "suite=threads"))
        test_suite = "AXIOM64_SUITE=threads";
    else if (word(cmd, "suite=network"))
        test_suite = "AXIOM64_SUITE=network";
    if (word(cmd, "phase=write"))
        test_phase = "AXIOM64_PHASE=write";
    else if (word(cmd, "phase=verify"))
        test_phase = "AXIOM64_PHASE=verify";
    else if (word(cmd, "phase=readonly"))
        test_phase = "AXIOM64_PHASE=readonly";
    else if (word(cmd, "phase=error"))
        test_phase = "AXIOM64_PHASE=error";
    else if (word(cmd, "phase=queue"))
        test_phase = "AXIOM64_PHASE=queue";
    else if (word(cmd, "phase=invalid"))
        test_phase = "AXIOM64_PHASE=invalid";
    else if (word(cmd, "phase=full"))
        test_phase = "AXIOM64_PHASE=full";
    else if (word(cmd, "phase=cond"))
        test_phase = "AXIOM64_PHASE=cond";
    else if (word(cmd, "phase=io"))
        test_phase = "AXIOM64_PHASE=io";
    else if (word(cmd, "phase=pressure"))
        test_phase = "AXIOM64_PHASE=pressure";
    memory_init();
    arch_init();
    auto modules = module_request.response;
    if (!modules || !modules->module_count)
        panic("missing root filesystem");
    vfs_init(modules->modules[0]->address, modules->modules[0]->size);
    block_init();
    boot_root_init(cmd);
    devices_init();
    net_init();
    log("Entering userspace in Ring 3\n");
    start_init("/sbin/init");
    __builtin_unreachable();
}
} // namespace ax
