# VM timing and accelerator benchmarks

Rotation's 16 MiB device files prefer the host's `/dev/shm` area when at least 16 MiB remains free after allocation. Files above 32 MiB and hosts without sufficient available space keep Linux disk backing. The NBD backend still owns the separate writeback cache, writethrough writes, actual flushes and injected faults. Actual device bytes are flushed to a persistent Linux checkpoint before final publication after success, timeout or rejection. These are guest crash tests; host-machine power loss is outside their scope. See the [Linux tmpfs documentation](https://docs.kernel.org/filesystems/tmpfs.html) for the host filesystem's lifetime.

A controlled local host-backend loop takes 1.638 seconds for 1,000 writethrough requests on disk and 0.005 seconds in host memory, with identical resulting disk hashes. One complete injected-error/recovery cell takes 57.039 and 29.699 seconds respectively, preserving its original images, seed, physical request prefix, failed virtio completion and exact recovered history. These focused measurements do not establish complete workflow performance. The 90-second guest deadline remains unchanged; the complete unsharded profile and full hosted workflow remain required.

The longest manager VM suites are measured with their full acceptance coverage. The successful [baseline CI run](https://github.com/frankischilling/Axiom64/actions/runs/38042782851) spent 746 seconds in normal-init UEFI acceptance and 761 seconds in a paired UEFI/modern/lane1 carrier/failure suite. These runs retain actual lease clocks, independent packets, device faults and desktop/keyboard checks.

The [complete 401-job scheduling baseline](https://github.com/frankischilling/Axiom64/actions/runs/38948650468) uses 52.656 runner-hours across a 6,082-second observed workflow span. Tool installation, shared-input download and extraction account for 33,291 runner-seconds across 399 workers. Its 256 rotation shards cover 64 distinct profiles. The scheduling combines each profile into one complete target run and pairs normal-init transports in isolated worker workspaces. Basic and expiry rotation profiles also share job input restoration and tool setup, with separate executions and retained evidence. All 3,840 rotation faults, 32 normal-init cases and 320 carrier cases remain required, along with every other suite and both aggregates.

A selected local TCG comparison passes eight normal-init cases under both sequential and paired execution, using the same actual kernel, default root and fixture sources. The sequential run takes 998.694 seconds; the paired run takes 663.274 seconds. The sequential measurement includes cold fixture preparation, so the complete hosted before/after run determines the workflow performance claim. A focused carrier comparison also passes both linkages for bound-carrier and failed-device cases while retaining the healthy interface's original twenty-second T1 observation. Full hosted acceptance and the complete unsharded storage profile remain integration gates.

The normal-init and carrier/failure harnesses accept `AXIOM64_QEMU_ACCELERATOR=tcg`, `auto` or `kvm`. Their default remains TCG. `auto` asks QEMU to initialize KVM and permits its initialization fallback to TCG; `kvm` requires KVM. QEMU's `query-kvm` response records the accelerator actually used in each result. A guest failure is a failed case, with no second emulator attempt. No guest clock or acceptance deadline changes.

The manual Build and boot workflow exposes the same `manager_accelerator` choice for measuring these two suite families. Other suites keep their current configuration. KVM access depends on the runner; the requested accelerator alone does not establish that KVM ran or improved performance. A local device-node probe could not initialize KVM, so local TCG fallback evidence cannot establish a KVM speedup.

The initial [strict-KVM run](https://github.com/frankischilling/Axiom64/actions/runs/38047203864) used actual KVM but failed three carrier cases. The same-head [TCG run](https://github.com/frankischilling/Axiom64/actions/runs/38047155925) completed all 352 scoped cases. KVM completed 339 successfully, failed three and left ten unrun. The 339 jointly successful cases took 12202.141 seconds in TCG and 12788.289 seconds in KVM when summed across their individual wall times. This failed, incomplete experiment does not establish a speed improvement; TCG remains the default.

The observer now waits for both manager and independent raw-socket EIO before checking removal. The manager retains an accepted interrupted hint across fresh unconfigured retries and clears that provenance on installation, missing/invalid cache or explicit invalidation. Shutdown retires an unconfigured interrupted retry without deleting its old accepted hint. These fixes require complete TCG and KVM acceptance; any future faster policy also requires complete measured improvement.

The later [same-head TCG run](https://github.com/frankischilling/Axiom64/actions/runs/38053360735) passed all 34 gates. Its [strict-KVM counterpart](https://github.com/frankischilling/Axiom64/actions/runs/38053360959) passed the carrier suites but failed the BIOS/modern/ext2/no-server normal-init desktop before keyboard injection. A single image request rejected the mapped xterm background before drawing; the failure-only screenshot subsequently showed its banner and prompt. The actual C probe reproduces this failure with delayed drawing on an owned native Xvfb; painting first passes. The probe now reads the same selected window at most twenty times, at 100 ms intervals, and still requires more than 100 different pixels. Permanently uniform images, exactly 100 different pixels and a missing window manager remain failures. `python3 scripts/tests/desktop_visual_test.py -v` covers these cases at the real probe/server seam. Complete VM acceptance remains required, including real keyboard acknowledgements in the same xterm.

The visual follow-up's [TCG run](https://github.com/frankischilling/Axiom64/actions/runs/38056484520) passed all 34 gates, with exact product checks for 352 scoped cases, four normal-init images and sixteen disks. Its [strict-KVM run](https://github.com/frankischilling/Axiom64/actions/runs/38056481964) passed all 32 normal-init cases but exposed another carrier-withdrawal ordering: carrier withdrawal cleared `installed` before receive EIO reached retirement, leaving accepted-hint provenance unset. A fresh unconfigured retry could then delete that hint on shutdown. Provenance now records the accepted lease at withdrawal, before its marker is cleared. `make test-manager-runtime-native` exercises the actual runtime withdrawal, retirement, fresh Client and shutdown with the real saved Store under sanitizers. Both event orderings retain accepted hints; unaccepted hints and explicit invalidation still delete them. Complete follow-up TCG and KVM acceptance remains required.

Measure focused profiles before changing the CI default. Preserve every scenario, linkage, firmware, transport, adapter lane and root type, explicit TCG coverage and all full CI gates. Publish exact sources/products and complete before/after timings. The healthy adapter's measured twenty-second T1 barrier remains required. Intermittent desktop keyboard acknowledgement still needs diagnosis.

The next [strict-KVM run](https://github.com/frankischilling/Axiom64/actions/runs/38059239922) exposed an observer failure in UEFI/modern/ext2/no-server. The completed log shows the required 1,000 ms restart interval, but a serial read ending partway through the timestamp could satisfy the parser's end-of-buffer anchor and fail the unchanged interval assertion. Spawn, reap and observer records now require their terminating newline. `python3 scripts/tests/normal_manager_events_test.py -v` checks every byte boundary of the captured restart and all three event types with LF and CRLF; it fails before the fix and passes afterwards. No clock, backoff bound or keyboard timing changes. Complete final acceptance remains required.

The separately measured [normal-init fixture compression work](ci-artifact-compression.md) retains every image and saved disk while reducing packaging CPU. Its archive size and hosted upload timing are separate from VM accelerator measurements.

The [complete TCP profile matrix](ci-tcp-profiles.md) distributes the six independent wire profiles across isolated jobs while retaining their original commands, waits and evidence. Its hosted comparison measures the serial TCP critical path separately from setup, queue time and the remaining manager suites.

The available mechanisms follow [QEMU's accelerator documentation](https://www.qemu.org/docs/master/system/qemu-manpage.html) and [GitHub's hosted-runner KVM guidance](https://github.blog/changelog/2024-04-02-github-actions-hardware-accelerated-android-virtualization-now-available/). This work concerns VM development infrastructure; HP work still follows the required VM prerequisites.

Rotation fault jobs restore a focused input archive with the same sources, file metadata, kernel and libc/provider products. Full root images and curl/OpenSSL build trees remain in the complete archive used by the other suites. This packaging split retains every required suite, fault target and real observation interval. Complete hosted before/after acceptance remains required for a workflow performance claim.

The expanded IPv6 device cohort reuses existing matrix cells. Its complete 180
guest profiles run with two workers in the IPv6-expiry job; all 45 native
comparisons remain in configuration. The preceding complete hosted workflow
measures configuration at 3,135 seconds, IPv6-expiry at 1,312 seconds and network
at 4,210 seconds. Its ready-only device steps take 431 guest and 206 native seconds.
The expanded local guest cohort takes 2,346 seconds; the native packet observations
span 1,048 seconds in total. Combining those measurements estimates about 98 minutes
for unsplit configuration, beyond its unchanged seventy-five-minute limit. Moving
the complete guest step estimates about 59 minutes for configuration and 61 minutes
for IPv6-expiry. These estimates do not establish a hosted performance improvement;
complete before/after workflow timings and matching evidence remain required.
Every state, action, linkage, firmware and adapter, full observation window,
per-profile deadline, zero-drop gate, original command and aggregate remains
required. Guest evidence is retained in `ipv6-device-wire`; native evidence stays
in `ipv6-configuration`. No jobs or matrix dimensions are added.

The [subsequent unsplit workflow](https://github.com/frankischilling/Axiom64/actions/runs/40145797237)
confirms the configuration limit: its job exceeds seventy-five minutes and is
cancelled, leaving 208 successful jobs and a failed `qemu` aggregate. Its passing
source, normal-image and GNU artifact audits do not make that workflow accepted.
The complete guest-step move above still requires a full hosted run and matching
independent evidence before any performance or integration claim.

## Rotation scenario scheduling

The complete [212-job baseline](https://github.com/frankischilling/Axiom64/actions/runs/40919695002) passes all required jobs and both aggregates. Its observed span is 5,847 seconds, with 168,614 summed job execution seconds and 303,926 summed queue seconds. Its 64 rotation jobs restore tools and prepared inputs separately for basic and expiry scenarios.

The matrix uses 32 rotation jobs, each running both scenarios in separate steps and directories. All 64 provider/linkage/firmware/transport/scenario/cache profiles keep one observed baseline apiece, every physical write/flush target, all three fault modes and the complete 3,840-case union. A failed basic step does not skip expiry, and either failure leaves the job failed. Each artifact keeps both scenario directories and their separate coverage indices. The coverage aggregate still rejects a missing or duplicated profile, changed source/product binding, missing target, altered deadline or incomplete fault-mode union.

This reduces required job dispatches from 212 to 180 and rotation artifact uploads from 128 to 64. The existing 75-minute job and 90-second guest limits remain. For each unchanged cell, the two measured baseline jobs sum to at most 2,396 seconds (39 minutes 56 seconds). Those sums establish a scheduling candidate, not a measured workflow speedup. Complete hosted before/after runs and retained actual coverage evidence remain required before a performance claim or integration.

`python3 -B scripts/tests/account_storage_ci_test.py -v` checks the complete observed target partition and executes the workflow's shell commands against a recording command fixture. It verifies all 64 profile arguments, distinct evidence paths and companion execution after either scenario fails. These tests establish dispatch and failure handling; actual guest executions, independent filesystem/content checks and published coverage indices establish recovery behavior.
