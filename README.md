# Axiom64

Axiom64 is an experimental native-first x86_64 operating system. The current
tree builds a UEFI loader, a freestanding C++20/assembly kernel, a generated
service initrd, an ext2 root disk, and a small BusyBox/musl userland that can
run under the Axiom64 boot-service and Linux syscall compatibility path.

The main development target is QEMU. The project is not a finished Linux clone:
native service IPC is the core architecture, while Linux support exists to make
selected dynamic BusyBox/musl workflows useful and testable.

## Reference Material

`../osdev-master` has been a major reference and a big help for research and
implementation of low-level boot, kernel, Linux ABI, and service-runtime work.
Axiom64 still keeps its own native-first architecture and service boundaries.

## Current Features

- UEFI boot handoff: the loader reads `kernel.elf` and `services.initrd`,
  discovers ACPI, GOP framebuffer, virtio-block root disk, xHCI, and serial
  state, then passes `BootInfo` version 3 into the kernel.
- Native microkernel runtime: the kernel owns early CPU setup, frame/page
  planning, service ELF materialization, ring-3 service entry, scheduler-owned
  service threads, syscall dispatch, fixed-layout IPC, and task-copy helpers.
- Boot service graph: the generated service initrd launches `init`,
  `processd`, `vfsd`, `blockd`, `ext2fs`, `devfs`, `ttyd`, `linuxd`,
  `inputd`, `usbd`, and `shelld`.
- Native shell entry: `shelld` exposes a small `> ` prompt with `help`, `ls`,
  and `/bin/ash` launch support before handing interactive work to BusyBox.
- BusyBox/musl userland: BusyBox 1.36.1 and musl 1.2.5 are staged into a
  generated ext2 root filesystem with `/bin`, `/dev`, `/lib`, `/usr/lib`,
  `/tmp`, `/root`, init/profile/passwd files, and applet symlinks.
- Linux ABI bridge: `linuxd` routes supported syscall families for VFS,
  process, memory, identity, time, futex, random, resource-limit, TTY, input,
  framebuffer-adjacent, and block work into native services; unrouted syscalls
  return `-ENOSYS`.
- Storage and filesystem services: virtio block, ext2 image traversal,
  symlinks, directory reads, generated device nodes, VFS descriptors, pipes,
  cwd/path state, and small `/tmp` and `/root` overlays are modeled in native
  service policy.
- Console and input paths: serial I/O, framebuffer console output, ANSI
  handling, scrolling, destructive backspace, canonical TTY buffering, PS/2
  fallback, and QEMU `usb-kbd` through xHCI, `inputd`, and `ttyd` are covered.
- Verification surface: host tests cover ABI tables, loader helpers, kernel
  runtime pieces, service policies, rootfs/initrd/ext2 structures, TTY/input,
  framebuffer, virtio, and xHCI models; QEMU smokes cover boot, root disk,
  BusyBox ash, job-control transcripts, and USB keyboard input.

## Quick Start

Run these commands from this directory:

```sh
tools/check-prereqs.sh
make build
make run
```

`make build` configures `build/` with Ninja and
`-DAXIOM_FETCH_USERLAND_SOURCES=ON`, then builds the boot image and generated
root disk. The first build downloads the locked BusyBox and musl source
tarballs into the build cache.

Useful verification commands:

```sh
make test
make boot-smoke
make interactive-smoke
```

`make run` starts QEMU with the generated UEFI image and ext2 root disk. At the
native `> ` prompt, type `ash` to launch BusyBox; use `Ctrl-A Ctrl-X` to leave
QEMU.

The QEMU helper defaults to a graphical framebuffer console with `usb-kbd`.
Set `AXIOM_QEMU_DISPLAY=none` for a headless run, or set `AXIOM_QEMU_RTC` when
you need a specific guest clock value. If OVMF is not installed in one of the
paths known to the QEMU scripts, set:

```sh
export AXIOM_OVMF_CODE=/path/to/OVMF_CODE.fd
export AXIOM_OVMF_VARS_TEMPLATE=/path/to/OVMF_VARS.fd
```

If a build directory has moved or CTest reports stale paths, configure a fresh
build directory.

## Manual Build

The Makefile is only a thin wrapper around CMake. The equivalent manual flow is:

```sh
cmake -S . -B build -G Ninja -DAXIOM_FETCH_USERLAND_SOURCES=ON
cmake --build build --target axiom_boot_image axiom_rootfs_image
ctest --test-dir build --output-on-failure
```

To include the QMP-driven USB keyboard smoke in CTest discovery:

```sh
cmake -S . -B build-usb -G Ninja \
  -DAXIOM_FETCH_USERLAND_SOURCES=ON \
  -DAXIOM_ENABLE_QEMU_USB_KEYBOARD_SMOKE=ON
ctest --test-dir build-usb -R '^qemu_usb_keyboard_smoke$' --output-on-failure
```

To use local BusyBox or musl source trees instead of fetching locked tarballs:

```sh
cmake -S . -B build-local -G Ninja \
  -DAXIOM_BUSYBOX_SOURCE_DIR=/path/to/busybox-1.36.1 \
  -DAXIOM_MUSL_SOURCE_DIR=/path/to/musl-1.2.5
```

## Repository Tour

- `boot/`: UEFI loader code for file loading, ELF loading, memory map capture,
  ACPI discovery, framebuffer discovery, virtio root disk discovery, xHCI
  discovery, and `BootInfo` construction.
- `kernel/`: freestanding kernel code for early x86_64 entry, serial and
  framebuffer console output, CPU tables, page tables, frame allocation,
  service image/runtime construction, scheduler state, syscall dispatch,
  service IPC, Linux task bootstrap, PS/2 input, and xHCI boot keyboard support.
- `libs/`: host-testable libraries for Linux ABI constants/syscall metadata,
  ELF64 parsing, and initrd v2 parsing.
- `servers/`: Linux syscall routing helpers used by the `linuxd` service policy.
- `services/`: native service models and runtime policies for init fanout,
  process/job-control state, VFS descriptors, pipes, path state, block reads,
  ext2 exec bundles, devfs, TTY, input, USB HID metadata, Linux syscall routing,
  and shell launch behavior.
- `recipes/`: locked BusyBox applet/config selection and minimal init files for
  `/etc/inittab`, `/etc/profile`, and `/etc/passwd`.
- `tools/`: prerequisite checks, UEFI image assembly, service initrd building,
  rootfs generation/checking, BusyBox/musl staging, and QEMU runners.
- `tests/`: the host test harness for ABI tables, boot info, UEFI helpers, ELF,
  initrd, rootfs manifests, ext2 structures, kernel runtime pieces, service
  policies, process/job control, VFS, TTY/input, framebuffer console, virtio
  queues, and xHCI keyboard handling.

## Generated Outputs

Common build products under `build/`:

- `boot/BOOTX64.EFI`: UEFI loader binary.
- `kernel/kernel.elf`: kernel image loaded by the UEFI loader.
- `services/*.elf`: freestanding service ELFs generated from the shared service
  runtime and per-service policy selection.
- `images/services.initrd`: initrd v2 image containing `/services/*.elf`.
- `images/axiom64-uefi.img`: FAT UEFI boot image containing the loader, kernel,
  and service initrd.
- `sysroot/`: staged BusyBox/musl root filesystem tree.
- `images/axiom64-root.ext2`: ext2 root disk image used by the root-disk and
  BusyBox smokes.

## Testing

`axiom64_tests` is the main host test binary. It covers source-level behavior
without booting QEMU, including:

- Linux syscall metadata and routing.
- UEFI boot info, ACPI, memory map, and root disk helpers.
- Kernel ABI/runtime pieces, IPC mailboxes, syscall frame decoding, scheduler
  helpers, page-table/runtime planning, and Linux task tables.
- Service runtime policies for init, process, VFS, block, ext2fs, devfs, TTY,
  input, USB, Linux syscall completion, and shell launch.
- Rootfs manifests, initrd v2 images, ELF images, ext2 image structures, virtio
  queues, framebuffer console rendering, PS/2 key decoding, and xHCI keyboard
  parsing/report delivery.

CTest also includes QEMU and rootfs smoke tests:

- `qemu_boot_smoke`: boots the UEFI image and checks serial boot markers through
  service scheduling and the native shell prompt.
- `qemu_boot_root_disk_smoke`: same boot path with the configured root disk.
- `rootfs_image_smoke`: checks the generated ext2 rootfs surface with `debugfs`.
- `rootfs_axiom_ext2_reader_smoke`: validates the ext2 reader tool against the
  generated rootfs.
- `rootfs_linux_bootstrap_smoke`: checks that the rootfs can provide the BusyBox
  and musl exec bundle needed for Linux task bootstrap.
- `qemu_busybox_interactive_smoke`: drives the native shell, launches BusyBox
  ash, checks prompts, `ls`, `clear`, `date`, redirects, pipes, scripts, sleep,
  Ctrl-C, Ctrl-Z, `jobs`, `bg`, `fg`, and cwd-sensitive prompts.
- `qemu_usb_keyboard_smoke`: injects keys through QEMU QMP into `usb-kbd` and
  checks that the xHCI/input/TTY path reaches BusyBox ash, including backspace.
