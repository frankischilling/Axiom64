# Userspace ports and provenance

The kernel implements the Linux x86-64 ABI itself. The host builds static tests, init, and BusyBox against source-built Ubuntu musl. The installed GNU toolchain starts with the Alpine musl interpreter and development libraries. The native image test rebuilds those libraries from the same pinned Alpine sources and patches. All of these libc builds apply the checked [DNS transport patch](../vendor/musl/README.md) and retain musl's MIT notices. The full image imports musl-linked packages from Alpine 3.22 x86-64. Their executables run against Axiom64's syscalls.

Native development tools are GCC 14.2.0, binutils 2.44, Make 4.4.1, and NASM 2.16.03. Desktop packages include Xorg 21.1.19, fbdev and evdev, twm, xterm 399, xeyes, bitmap fonts, Bash 5.2.37, and zsh 5.9. The native toolchain test assembles an x86-64 ELF object and links and calls it from C. It also checks compiler diagnostics and builds a C++ shared library inside the guest. A separate executable loads the library with `dlopen`, catches its exceptions across the library boundary, and verifies that two threads use independent thread-local state.

The installed desktop profile sets Thunar 4.20.3 as the system default for folders and adds a shortcut to each account's desktop. The profile includes the GTK runtime, icons, and shared MIME database. The graphical session builds the image loader cache under the user's cache directory. The port manifests pin the packages and the corresponding source recipes.

All image profiles ship the pinned Alpine D-Bus 1.16.2 daemon, tools and client library. The source bundle carries the upstream sources, notices and Alpine recipe. The test probe builds against the matching development headers, which stay out of the boot images. See [the D-Bus service and session setup](accounts.md#d-bus).

The [installed desktop profile](disk-root.md) adds kitty 0.42.1, its X11 backend,
the `kitten` helper, terminal definitions, Python, and DejaVu fonts. Mesa
llvmpipe provides OpenGL for the framebuffer X server. The source bundle
includes the pinned Alpine recipes, the Go runtime and modules linked into
`kitten`, and the release archive for its bundled symbol font. The full and
desktop profiles use the smaller framebuffer session with xterm.

The installed desktop also ships btop 1.4.0. It reads live CPU and memory data,
process names and arguments, and mounted filesystem capacity. The first desktop
login adds a btop shortcut and creates a default configuration that uses the
live mount table. Existing user configurations take precedence. Network and disk
throughput still need hardware validation.

The installed desktop includes OpenSSH 10.0p1 and Pure-FTPd 1.0.52. The package
and source locks include their release archives and Alpine patches. Both use
the pinned OpenSSL runtime already in the image. Set up and start each listener
from the console using the [remote testing guide](pxe.md).

All profiles ship Weston 14.0.2 with the X11 backend, Pixman renderer, desktop shell, terminal, shared-memory demo, and `wayland-info`. The port locks record the packages and sources. The builder selects the nested desktop and its supporting libraries from those packages. Weston creates a private socket directory for each invocation and removes it on normal exit or handled signals. A login-wide `XDG_RUNTIME_DIR`, standalone DRM/KMS, accelerated rendering and Xwayland remain open.

`make test-guest-kernel` imports the kernel sources into an isolated guest and builds `build/axiom64.elf` using the installed GNU tools and NASM. It verifies the source digests inside Axiom64, checks the ext2 export, and packages the resulting ELF with the existing root filesystem for the full BIOS and UEFI boot suite. Set `AXIOM64_KERNEL_BUILD_ACCEL=kvm` to accelerate compilation on hosts with KVM. Results and the exported kernel are retained under `build/guest-kernel-*`.

Run `make test-guest-kernel GUEST_KERNEL_FLAGS=--source-tools` to build GNU Make and NASM from the locked source releases inside Axiom64, then use those binaries to build the kernel. Installed GCC and binutils provide the initial toolchain. The guest checks both source archive hashes before extraction.

`make test-guest-system` rebuilds GNU Make, NASM, the kernel, and musl inside Axiom64. The guest installs musl headers, startup objects, libraries, and compiler specs alongside the pinned Linux UAPI headers. It also builds the stack-protector support archive from the pinned Alpine recipe source. It uses that sysroot to build init, both ABI clients, and static BusyBox 1.37.0. The linker maps show which libc files the static and dynamic clients used.

The guest puts those files in an initramfs and authors a bootable ISO with xorriso, the pinned bootloader binaries, and a guest-built Limine installer. The verifier checks the ext2 export and the dynamic client's interpreter, then runs the BusyBox shell and both ABI clients in fresh BIOS and UEFI boots. Run this check with `make test-suite SUITE=guest-system` or as part of `make test-suite SUITE=root-userspace`. Both retain the disk, image and results under `build/guest-kernel-*`. QEMU tries KVM first and records the accelerator it uses. The full installed root filesystem still uses the host build pipeline.

The native build applies a [local GNU Make 4.4.1 patch](../vendor/make/environment-prefix.patch) that bounds environment-name matching. The guest checks the build inputs before use and unmounts each temporary workspace once its outputs have been copied. It stages the new sysroot on the ext2 export disk so its headers and libraries leave room for compiler files in RAM. Host and guest BusyBox builds share the [configuration script](../scripts/configure-busybox.sh).

Run `make test-guest-binutils` to build the pinned GNU assembler, BFD linker, and binary utilities inside Axiom64. The host prepares a read-only ext2 source disk from the checked release and distribution patches. The guest verifies every regular source file before compiling in a RAM workspace. Pinned Bison, Flex, and m4 regenerate the linker parser and lexer from the patched sources. The guest exports the installed tools, release manual pages, and upstream licenses to a second ext2 disk. Fresh BIOS and UEFI boots use the exported assembler and linker to build and run static and dynamic C clients with an assembly input. The source hashes, package, disk check, and boot logs are under `build/guest-binutils-*`.

Use `make test-guest-binutils GUEST_BINUTILS_FLAGS="--release 2.46"` to build the signed GNU release inside Axiom64. The test checks the detached signature and the pinned archive and leaves the released parser and lexer files intact. The default command still builds the patched distribution release, binutils 2.44. Both versions use the same guest compile, ext2 export, and installed-tool checks.

`make cross-toolchain` builds GNU binutils 2.46 and GCC 16.1 on x86-64 Linux. It installs C and C++ drivers, `libgcc`, `libatomic`, and `libstdc++` under the prefix it prints. The drivers target x86-64 musl and use the pinned, source-built musl libraries and Linux UAPI headers in that prefix. The build log and file manifest stay under `build/cross-toolchain/`. On a case-insensitive mount, the builder uses the Linux user cache to preserve Linux headers whose names differ only by case.

Run `make cross-toolchain-sources` to fetch and authenticate the GNU releases and GCC prerequisites. The source bundle includes these archives, detached signatures, and the release keys. For an offline build from the populated download cache and an existing musl sysroot, use `make cross-toolchain CROSS_TOOLCHAIN_FLAGS="--offline --sysroot /path/to/sysroot"`. The supplied sysroot must contain musl headers, startup objects and libraries, the musl interpreter, and Linux UAPI headers. Keep the printed prefix in place because the GCC drivers record paths to the assembler, linker and sysroot.

Run `make test-cross-toolchain CROSS_TOOLCHAIN_PREFIX=/path/to/install` to verify the installed cross tools. It checks the header dependencies and linker inputs, rejects linking against an empty sysroot, then boots the cross-linked static and dynamic C clients and shared C++ exception and thread-local state test under BIOS and UEFI.

`dependencies.json` pins the bootloader, protocol header, BusyBox, libcap and OpenSSL by SHA-256. `ports.lock.json` pins APK URLs, versions, SHA-256, license labels, upstream sites, origins, and source commits. A package can also declare a checked `vendored_archive` under [`vendor/ports`](../vendor/ports/README.md), preserving its original bytes when an upstream repository stops serving that version. Root filesystem assembly treats package contents as data and never runs installation hooks. Font indexes are generated explicitly. Mesa's renderer, LLVM, and SPIR-V payloads are omitted because the image uses fbdev with GLX disabled.

Upstream libcap 2.78 supplies installed `getcap` and `setcap` tools, linked against the runtime musl provider. The build elects libcap's BSD-3-Clause option, retains its complete upstream `License`, and includes the SHA256-verified archive in the source bundle. Static and dynamic fixture tools use the explicit build provider; native Linux tools retain their actual libc and startup inputs. [File capability verification](file-capabilities.md#upstream-tools-and-verification) records the tool, source and runtime provenance.

OpenSSL 3.5.9 builds from its pinned upstream archive. Static and shared target builds use the explicit musl providers and verified Linux UAPI headers; the native comparison records its actual libc and startup inputs. Both ordinary rootfs profiles install the runtime provider's shared libraries, executable, headers, configuration and legacy module. The upstream archive, detached release signature, build recipe and complete Apache-2.0 notices are retained. The recipe selects OS seed sources and checks the executable interpreter and dependencies. [Runtime verification](random.md#verification-and-remaining-work) covers real TLS 1.2/1.3 clients, certificate rejection, key generation, package signatures, initialization waits and actual provider loading in native comparisons and both firmware/transport variants.

The image recipe builds the OpenSSL libraries, command and modules with
`no-tests`. Axiom64's crypto checks exercise the staged binaries and libraries
that the image ships.

Build all providers with `make openssl`. Case-sensitive Linux storage preserves the complete pinned UAPI archive when the workspace is on a Windows mount. Caches validate their recipe, provider, source, library and product identities before reuse. Shared modules remain enabled; the shared client checks actual default and legacy provider loading.

Curl 8.23.0 and libcurl build from the authenticated upstream release. `make curl` selects the explicit build-musl, runtime-musl and native comparison providers, retaining static/shared products, the detached signature, release key, notices and build inputs. The recipe enables IPv6 and threaded resolution; those build options do not establish guest support for every protocol. Optional compression, internationalized names, public-suffix handling, SSH transports and HTTP/2/3 dependencies remain planned. The [download checks](testing.md) retain actual HTTP/HTTPS runtime, installed-image and published-byte evidence.

Installed `curl-config` and pkg-config metadata use target compiler and `/usr` paths. Their original generated bytes and the actual configure/build commands remain in the producer record. Static curl uses Libtool's `-all-static` program link option; executable dependency checks reject a dynamic interpreter or library dependency in that profile.

Local curl checks cover complete HTTP binary bodies, chunked framing and trailers, redirects, resumed transfers, truncation, HTTP errors, output permissions and deadlines. HTTPS checks exercise TLS 1.2/1.3 and reject wrong names, unknown issuers, expired certificates and certificates that are not yet valid. Both musl providers and linkages run across BIOS/UEFI, modern/legacy virtio and e1000. A separate normal-image pilot verifies authenticated desktop login, production DHCP/DNS, administrator-selected default trust and downloads retained across a fresh kernel. The normal-image and artifact gates require every selected provider/linkage/firmware/transport cell and the complete current workflow.

BusyBox `wget` uses the installed OpenSSL helper for HTTPS when available. Native and guest checks verify issuer and DNS-name rejection with the default trust store, including missing and damaged stores. The pinned upstream helper passes a numeric address with its explicit port to `-verify_ip`; that helper exits before a TLS handshake. Use `curl` for numeric-IP HTTPS URLs. When the helper is absent, wget's internal TLS 1.2 fallback accepts an untrusted issuer and wrong name, and prints `TLS certificate validation not implemented`. Use curl when authenticated HTTPS is required; the internal wget fallback does not provide certificate validation. BusyBox remains unmodified upstream source.

`make ca-bundle` checks the dated Mozilla-derived trust bundle and its exact source revision. The unmodified upstream converter reproduces every published byte at the bundle's recorded data date; independent TLS parsing checks all 121 certificate DER values. The rootfs builder installs the public bundle at `/etc/ssl/cert.pem`, with the MPL-2.0 notice and source manifest. This PEM representation does not carry the browser's additional trust restrictions. Download clients use the actual guest clock for certificate validity checks. Private test authorities belong only in explicit test fixtures or administrator-selected trust configuration.

The [account tools](accounts.md) use source-built libxcrypt 4.5.2. The builder checks the archive, detached release signature, public-key fingerprint and LGPL-2.1-or-later notices. It selects maintained strong hashes and uses initialized kernel output for fresh yescrypt salts. Static and shared builds use the explicit libc providers and the same complete pinned Linux UAPI header module as OpenSSL. Source, staged products and compilation inputs remain traceable in the producer manifest and source bundle. `make libxcrypt` builds all providers; `make test-password-library-native` exercises the actual password helper through six native linkage/provider combinations. Account storage and authenticated guest sessions have separate runtime checks; a library build alone does not establish those requirements.

The account generation store now has a small transaction interface under `userspace/accounts/`. It validates root ownership, exact modes and regular-file link counts, holds a process lock, reads one immutable passwd/group/shadow generation, and publishes the three complete files through one atomic pointer replacement. Public lookup files use mode 0644 and shadow uses 0600. A commit reports whether publication happened when a later durability operation fails; callers must inspect the current state before recovering. Normal successful updates retain the current and preceding generation. Missing or damaged current state with existing generations fails closed instead of starting provisioning again.

`scripts/account_store_test.py --fixtures /tmp/axiom64-account-store-check` exercises six native libc/linkage profiles in a fresh Linux filesystem directory. `scripts/account_store_guest.py` runs the same real filesystem, twelve concurrent-update, ordinary-user denial, metadata rejection and restrictive-umask controls in eight fresh BIOS/UEFI RAM-root configurations. `scripts/account_store_ext2.py` adds sixteen persistent cells across both libc providers, linkages, firmware types and virtio block transports. Each cell updates a real ext2 disk, verifies raw host-exported payloads and metadata, and reads the same generation from a second independent kernel boot; all 32 filesystem checks pass. The helpers record source, compiler, product, log and process provenance. The [account tools](accounts.md) also validate record relationships, perform root account management and real libc lookup, and run maintained password decisions, private terminal entry and two concurrent ordinary shell sessions across six native and eight guest profiles per suite. Local login, su, sudo, password changes and durable session records have focused runtime checks. Normal images create an administrator privately on first boot and require login on later boots; ten normal-image boots and two persistent full-image boots verify these flows locally. Authenticated graphical sessions pass the full RAM/ext2 firmware matrix; complete persistent administration, storage/process/VM crash recovery and final complete CI remain unfinished.

`sources.lock.json` pins exact Alpine APKBUILD recipes and their source and patch checksums. Sources come from Alpine's distfile cache or the recipe's exact repository commit and are checked with SHA-512. Recipe bodies are preserved as text and never executed by the fetcher. The lock also pins Ubuntu's source package for static programs' musl.

Login-record verification uses a [portable GNU reader kit](../vendor/gnu-utmp-reader/README.md) with its own pinned inputs. Its Ubuntu package and source URLs use the dated archive snapshot from 8 November 2026 so package rotation does not remove required inputs. Exact versions, sizes and checksums remain pinned. It stages GNU libc headers and static libraries, GCC runtime inputs and exact Linux errno headers without ambient host libraries. The kit records the actual compilation/link inputs and includes its application object and a relink script. Moved-kit relinking reproduces the reader bytes, and source bundling preserves the upstream archives, required notices and kit. This reader establishes GNU login-record interoperability; wider source-built glibc and NSS support remain planned.

The desktop image includes Chocolate Doom 3.1.1 and both Freedoom 0.13.0
campaigns. The engine builds against the pinned musl toolchain and the
locked Alpine SDL2, SDL2_mixer, and SDL2_net packages. SDL2 headers stay in
the build sysroot. The engine's local patches handle SDL's unlimited
software texture dimensions and X11 navigation keys with mismatched
scancodes. The builder verifies the signed Freedoom checksum before
installing the original IWADs and preserves the engine license and
Freedoom credits.

Run `python3 scripts/doom_test.py --nvme --output build/doom-nvme-test` after
building the kernel and desktop archive. Each campaign boots from its own
UEFI NVMe disk. The test checks both launchers, plays a level with keyboard
input, compares rendered frames, and records the emulated HD Audio output.

The image includes `cupidfetch` for a terminal system report. An ordinary
user can run `cupidfetch --json` to read the Axiom64 identity, kernel release,
uptime, CPU, and memory. The builder compiles CupidFetch from pinned source
and includes its license in the image and source bundle.

Launch either campaign from the X11 Games menu or with
`freedoom 1` and `freedoom 2`. Both have desktop entries under
`/usr/share/applications`. The authenticated desktop seeds matching
shortcuts in a user's `Desktop` directory and preserves existing files.
With an Intel HD Audio device present, the user needs write access to
`/dev/dsp` to use SDL's OSS backend. For a regular account, an
administrator can grant membership in the audio group with GID 29.

The image includes copyright and license notices under `/usr/share/licenses`, plus port and source manifests. Produce the companion source bundle with:

```sh
make sources
```

`build/axiom64-sources.tar` contains upstream sources, patches, recipes, manifests, the BusyBox configuration, and Axiom64 build sources. Python and shell build helpers retain their paths under `scripts/`, including the CI tool setup recipe. CI publishes it beside the boot artifact. Recipes describe the distribution's build options and patches; Axiom64 does not claim to reproduce every distribution binary bit for bit.

Updating ports is an explicit maintenance operation. Resolve package roots with `scripts/ports.py resolve`, refresh recipes with `scripts/sources.py resolve`, review both locks, and run the full firmware tests. Ordinary builds use committed locks. Source caches reject changed checksums; remove an outdated cached patch before fetching its new pinned revision.

Musl's build cache uses the selected source entry, local musl patches, build recipe, and compiler. Adding an unrelated desktop port keeps the existing musl build available.
