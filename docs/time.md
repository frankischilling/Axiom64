# Clocks and elapsed kernel waits

The kernel exposes a boot-relative clock with 10 ms resolution. A free-running
counter supplies elapsed time; the 100 Hz PIT continues to supply scheduling
interrupts. Reading the clock at syscall entry and exit also accounts for time
spent in synchronous kernel operations with interrupts disabled.

Previously, the clock counted only PIT interrupts. A real three-second ext2
flush advanced `CLOCK_MONOTONIC` by just 10 ms because pending interrupts
coalesced during block polling. The controlled regression now observes the
flush interval and verifies that a child's absolute futex timeout and a two-second interval
timer become due across that operation.

## Counter selection

1. Prefer a 64-bit HPET main counter discovered through a checked ACPI table.
   Validate RSDP signatures/checksums, bounded RSDT/XSDT entries, HPET checksum
   and memory register address, hardware identity, counter width, period, and
   actual counter progress. Comparator registers must fit the checked 1 KiB
   device window (3–24 comparators). Enable the main counter with legacy replacement
   and comparator interrupts disabled, preserving PIT scheduling.
2. If HPET is absent or unusable, calibrate the TSC against five independent
   PIT channel-2 intervals. Select the shortest completed sample to avoid
   treating a delayed polling observation as the frequency. Restore the
   speaker/gate bits. This fallback supports a fixed-frequency single-CPU
   system; calibration does not prove stability through frequency changes,
   migration, or suspend/resume.
3. If neither counter is usable, retain IRQ-only time accounting. Its serial
   message identifies that elapsed kernel waits cannot be accounted for.

Limine base revision 3 returns the RSDP physical address and leaves ACPI and
reserved regions outside the direct map. The architecture reader checks the
firmware memory range and maps those bytes explicitly. It uses the existing
supervisor-only, uncached MMIO mapper, which rejects conflicting RAM mappings.
Bootloader-reclaimable firmware bytes already have a direct mapping. No table
read exceeds 64 KiB; root tables have at most 256 entries, and extended RSDP
records have at most 4096 bytes. Corrupt or unsupported tables fall back without
following their unchecked sizes or pointers.

`Clock::Counter` copies its scale and initial reading. It carries fractional
10 ms units across samples, admits small unsigned wrap, ignores ambiguous
backward differences larger than `INT64_MAX`, and saturates accumulated time.
Its common path uses bounded 64-bit arithmetic. Large intervals use a quotient
and remainder calculation with at most 27 steps, avoiding a freestanding
128-bit division dependency.

## Boundaries and current limits

Timer interrupts refresh time before polling devices, readiness, and signals.
Syscalls refresh it before dispatch and after completion. Existing sleepers
and deadlines therefore see elapsed storage time when control returns. The
kernel continues to execute synchronous block operations without preemption;
this change does not promise that an overdue callback can run during them.
The virtio transport's existing two-second reset and 30-second block-request
deadlines retain their independently calibrated implementation and policy.

`clock_getres(CLOCK_MONOTONIC)` remains 10 ms. The currently accepted
`clock_gettime` IDs share the boot-relative clock; `CLOCK_REALTIME`,
`gettimeofday`, and `time` do not supply an RTC-derived calendar date. Complete
Linux clock-ID semantics, RTC/realtime setting and permissions, ACPI PM timer,
higher-resolution deadlines, SMP clock handling, power transitions,
suspend/resume, and synchronization remain in
[the clocks/timers/power scope](https://github.com/frankischilling/Axiom64/issues/16).

## Verification

```sh
make test-clock-codec
make test-clock
python3 scripts/clock_test.py --firmware bios --transport modern --counter tsc --delay 3
```

Native GNU ASAN/UBSAN checks 4096 counter fixtures against independent 128-bit
arithmetic (49152 samples), fractional intervals, invalid scales, backward
readings, wrap, and saturation. ACPI fixtures include five valid layouts,
29 malformed cases, and 16000 bounded mutations. Invalid parsing preserves
the caller's previous result.

The guest matrix contains 24 boots: BIOS/UEFI, modern/legacy virtio, normal HPET,
HPET disabled for TSC fallback, or an unsupported 32-comparator HPET requiring
TSC fallback, and zero/three-second backend flush delay. Each
case starts from a byte-identical copy of one disposable ext2 seed. The host
retains seven independently timed flushes and compares the guest's mount/fsync
intervals with those durations. Delayed cases also require the child's absolute futex timeout and
interval timer to expire, and every case verifies ordinary sleep intervals,
boot-relative clock agreement, explicit guest success, and the selected
counter. The child deliberately yields after reporting its absolute deadline,
so entering the wait after storage must observe an already expired timeout.
The seed must remain unchanged.

Results are in `build/clock-results.json`; guest/backend logs and flush traces
use `build/clock-*`. Existing full OS, networking, thread, storage, and root
tests remain separate required gates.

Primary references: [Limine protocol, base revision 3 and RSDP](https://github.com/limine-bootloader/limine-protocol/blob/trunk/PROTOCOL.md),
[ACPI HPET table layout](https://github.com/torvalds/linux/blob/v6.12/include/acpi/actbl1.h),
and [QEMU HPET counter implementation](https://github.com/qemu/qemu/blob/v8.2.2/hw/timer/hpet.c).
