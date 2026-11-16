# Project goals and release requirements

Axiom64 is a standalone x86-64 operating system written primarily in C++20 and Assembly. The goal is a reliable, self-hosting, GNU/Linux-like system for daily development and testing. Its modular monolith kernel owns memory, scheduling, filesystems, networking and drivers behind internal interfaces. Init, services, shells, compilers and applications run in separate Ring 3 processes.

Linux is the only userspace ABI target. Expand Linux x86-64 compatibility first, retain planned Linux i386 support, and develop wider runtime support through tested interfaces. The excluded non-Linux executable personalities require a new scope decision before implementation.

The end goal is an everyday development and testing system on the HP EliteOne 800 G3 recorded in [HP hardware readiness](feature-roadmap.md). It must provide a browser, editors, development tools, audio and video, SSH, graphical remote access and file transfer. Booting a shell or bundling packages does not satisfy this goal.

## VM first, HP second

Finish the operating system in virtual machines before starting the HP hardware phase. Most feature and application requirements must have acceptance evidence, including every prerequisite for the required workloads. A completed subset leaves its wider feature area unfinished when requirements remain.

The sequence is:

1. Implement the required OS features and emulated-device drivers, and demonstrate the complete testing environment in VMs. Preserve BIOS/UEFI, storage, Linux ABI, networking, threading and desktop checks. Record remaining requirements and their effect on the intended system.
2. After VM readiness, implement and validate the HP-specific platform and driver work against the inventory in HP hardware readiness. UEFI removable media, display, USB input and the machine's required devices belong to this phase. Complete the required drivers before beginning HP boot tests.
3. Verify the resulting system on the actual HP machine, then establish installation readiness. Physical input, display, storage, Ethernet, audio, video and sustained combined workloads need evidence from that machine.

Complete VM workload evidence and the readiness review establish when the hardware phase can begin. An individual passing VM test does not satisfy that review or establish support for physical devices absent from the emulated platform. In particular, QEMU e1000 support does not establish I219-LM support, PS/2 input does not establish USB HID support, and virtio disks do not establish AHCI or NVMe support.

## Required everyday workloads

| Workload | Required result | Related requirements |
| --- | --- | --- |
| Browser | At least one real Firefox or Chromium browser supports normal graphical browsing through the guest's network stack, with working input, text rendering and HTTPS. Either browser is acceptable. | [browser support](application-roadmap.md); networking, Linux ABI and executable loading, display servers and desktops |
| Editors | Edit, save and reopen source and text files on persistent guest storage; use editors alongside terminals and builds in the desktop. | base commands, native development, filesystems, terminals and desktops |
| Development | Use native GNU C/C++ tools and a maintained sysroot; expand build tools, debuggers, language runtimes and package builds toward full self-hosting. | native development and self-hosting, debugging and tracing, GNU toolchain development |
| Audio and video | Play and capture real audio through supported devices, and run video playback with functional rendering, sound and input. Dummy backends do not satisfy the requirement. | audio, display servers/graphics, GNU toolchain development, HP hardware readiness |
| Remote access | Provide SSH terminals, graphical remote access and file transfer, with working authentication and appropriate transport protection. All three are required. | [remote access](application-roadmap.md); credentials, secure randomness and networking |
| Persistent operation | Preserve files and configuration across clean reboot, recover from expected device and service failures, and run combined desktop, build, storage and network workloads. | storage, filesystems, mounts, login, services, reliability and HP hardware readiness |

This table defines required workloads. The [application catalog](application-roadmap.md) remains the wider ports plan; it is not limited to this first set of everyday tasks.

## Development and compatibility

Develop foundations in dependency order. Persistent storage and mount ownership
support the distribution. Threads, retained I/O and clocks support applications
and drivers. Network transports support DNS, downloads and remote access.
Credentials, permissions and secure randomness must work before remote services
are exposed. The [feature roadmap](feature-roadmap.md) tracks the required areas
and their dependencies.

Linux compatibility includes syscall arguments, structures, errors, flags,
signals, descriptor ownership, executable loading and the behavior real programs
depend on. Use Linux source, UAPI definitions and applicable protocol standards
to establish these contracts. Keep kernel subsystems behind clear internal
interfaces and put services and applications in userspace where appropriate.

Maintain a reproducible source-built GNU cross and native toolchain, an explicit
target sysroot and a documented patch series. Imported tools that compile guest
programs are a useful baseline; they do not establish reproducible toolchain
builds or complete self-hosting. Full self-hosting requires building the OS and
packages inside Axiom64 and booting the resulting system. See [ports](ports.md).

Keep source versions, hashes, licenses, dependencies, build options, patches and
installation manifests traceable. Prevent target builds from using host headers,
libraries or executables accidentally. When a port exposes missing functionality,
implement that functionality rather than disabling useful application behavior.
Prefer GNU utilities where they improve development or everyday use. Extend the
software catalog as useful prerequisites become available.

Develop X11 and Wayland as parallel desktop targets. The wider
[application roadmap](application-roadmap.md) remains required alongside the
initial everyday workloads above.

## Accounts and startup policy

Normal images must create an administrator privately on first boot and require
login on later boots. Passwords are entered in the guest or supplied through
protected provisioning. Keep the root account locked. Elevation requires the
administrator's password and current authorization. Missing, damaged or
unavailable account state must block authentication.

Account and session checks must cover ordinary identities, private display
authorization, concurrent users, keyboard input, logout, supervisor/display
failure and persistent recovery. Explicit test fixtures may provision accounts;
release images and real credentials must remain separate from those fixtures.
Wider service integration and storage power-loss recovery remain release
requirements even when a focused account or desktop comparison passes.

## Evidence and readiness review

Subsystem documents describe supported behavior and its limits. A particular
build needs evidence tied to its actual source, programs, images and observations.
Keep imported, buildable and runtime-verified software distinct. Compilation,
boot banners, bundled packages and test summaries alone do not establish a
working feature or a usable operating system.

Before integration, require every job and aggregate in the full workflow for the
proposed revision, plus its required source, product and runtime checks. Preserve
BIOS/UEFI, static/dynamic linkage, native comparisons, device variants, sanitizers,
filesystem checks and actual guest workloads. Keep original clocks, observation
windows and deadlines. Failed, cancelled, skipped or missing required work is
not acceptance. Source changes and relevant integration changes require fresh
qualification; historical success retains its original scope.

The VM-readiness review must identify each required workload and prerequisite,
its tested implementation and supporting evidence, remaining requirements and
their effect on the HP target. Include storage persistence and recovery, usable
input/display, network and remote services, native development, browser,
audio/video and sustained combined workloads. Keep wider feature areas open
until their complete acceptance criteria are met.

After VM readiness and the required HP driver work, begin physical acceptance
with the agreed removable-media UEFI workflow. Installed disks and partitions
are not disposable media. Destructive disk, installer, EFI and firmware actions
require explicit device selection and authorization. Physical device and workload
claims need evidence from the actual machine.

## Build efficiency and documentation

Measure build, execution and queue time before changing CI. Reuse verified caches,
share identical inputs and overlap independent work with isolated outputs.
Compare complete before/after workflows and preserve every required scenario and
failure observation. Do not conceal failures or retry unchanged failed producers
until they pass. Reader-only corrections should reopen original successful
executions without presenting a regenerated run as the earlier result.

Keep generated files bounded. After integration and evidence retention, remove
completed staging trees, duplicate images and compiler intermediates. Preserve
active work, useful pinned source/toolchain caches and concise diagnostics.
Inspect contents and task-owned processes before cleanup; a clean Git status
alone does not establish that a directory is disposable.

Keep the root README concise. Put architecture, builds, subsystem contracts,
testing, ports, limitations and recovery instructions under `docs/`. Use
[architecture](architecture.md), [source layout](source-layout.md),
[build instructions](build.md), [testing](testing.md) and
[milestones](milestones.md) as entry points. Keep historical execution records
with their evidence and development tracking. Private questions, answers and
reference details stay in the ignored working record, outside public source
bundles and releases.
