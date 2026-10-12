# Userspace ports and provenance

The kernel implements the Linux x86-64 ABI itself. Static tests, init and BusyBox use source-built pinned Ubuntu musl. The installed interpreter and development libraries use source-built pinned Alpine musl. Both apply the checked [DNS transport patch](../vendor/musl/README.md), retain musl's MIT notices, and record input, patch and product hashes. BusyBox 1.37.0 is built from upstream without Axiom64-specific BusyBox patches. The full image also imports Linux-ABI, musl-linked packages from Alpine 3.22 x86-64. Their executables run against Axiom64's syscalls.

Native development tools are GCC 14.2.0, binutils 2.44, and Make 4.4.1. Desktop packages include Xorg 21.1.19, fbdev and evdev, twm, xterm 399, xeyes, bitmap fonts, Bash 5.2.37, and zsh 5.9. Tests compile and execute new programs with the imported native toolchain.

`dependencies.json` pins the bootloader, protocol header, BusyBox, libcap and OpenSSL by SHA-256. `ports.lock.json` pins APK URLs, versions, SHA-256, license labels, upstream sites, origins, and source commits. Root filesystem assembly treats package contents as data and never runs installation hooks. Font indexes are generated explicitly. Mesa's renderer, LLVM, and SPIR-V payloads are omitted because the image uses fbdev with GLX disabled.

Upstream libcap 2.78 supplies installed `getcap` and `setcap` tools, linked against the runtime musl provider. The build elects libcap's BSD-3-Clause option, retains its complete upstream `License`, and includes the SHA256-verified archive in the source bundle. Static and dynamic fixture tools use the explicit build provider; native Linux tools retain their actual libc and startup inputs. [File capability verification](file-capabilities.md#upstream-tools-and-verification) records the tool, source and runtime provenance.

OpenSSL 3.5.9 builds from its pinned upstream archive. Static and shared target builds use the explicit musl providers and verified Linux UAPI headers; the native comparison records its actual libc and startup inputs. Both ordinary rootfs profiles install the runtime provider's shared libraries, executable, headers, configuration and legacy module. The upstream archive, detached release signature, build recipe and complete Apache-2.0 notices are retained. The recipe selects OS seed sources and checks the executable interpreter and dependencies. [Runtime verification](random.md#verification-and-remaining-work) covers real TLS 1.2/1.3 clients, certificate rejection, key generation, package signatures, initialization waits and actual provider loading in native comparisons and both firmware/transport variants.

Build all providers with `make openssl`. Case-sensitive Linux storage preserves the complete pinned UAPI archive when the workspace is on a Windows mount. Caches validate their recipe, provider, source, library and product identities before reuse. Shared modules remain enabled; the shared client checks actual default and legacy provider loading.

The account work in [#115](https://github.com/frankischilling/Axiom64/issues/115) adds a source-built libxcrypt 4.5.2 port. The builder checks the archive, detached release signature, public-key fingerprint and LGPL-2.1-or-later notices. It selects maintained strong hashes and uses initialized kernel output for fresh yescrypt salts. Static and shared builds use the explicit libc providers and the same complete pinned Linux UAPI header module as OpenSSL. Source, staged products and compilation inputs remain traceable in the producer manifest and source bundle. `make libxcrypt` builds all providers; `make test-password-library-native` exercises the actual password helper through six native linkage/provider combinations. Account storage and authenticated guest sessions remain under development; a library build alone does not establish those requirements.

`sources.lock.json` pins exact Alpine APKBUILD recipes and their source and patch checksums. Sources come from Alpine's distfile cache or the recipe's exact repository commit and are checked with SHA-512. Recipe bodies are preserved as text and never executed by the fetcher. The lock also pins Ubuntu's source package for static programs' musl.

The image includes copyright and license notices under `/usr/share/licenses`, plus port and source manifests. Produce the companion source bundle with:

```sh
make sources
```

`build/axiom64-sources.tar` contains upstream sources, patches, recipes, manifests, the BusyBox configuration, and Axiom64 build sources. Python and shell build helpers retain their paths under `scripts/`, including the CI tool setup recipe. CI publishes it beside the boot artifact. Recipes describe the distribution's build options and patches; Axiom64 does not claim to reproduce every distribution binary bit for bit.

Updating ports is an explicit maintenance operation. Resolve package roots with `scripts/ports.py resolve`, refresh recipes with `scripts/sources.py resolve`, review both locks, and run the full firmware tests. Ordinary builds use committed locks. Source caches reject changed checksums; remove an outdated cached patch before fetching its new pinned revision.
