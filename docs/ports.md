# Userspace ports and provenance

The kernel implements the Linux x86-64 ABI itself. Static musl tests and init use the pinned Ubuntu musl toolchain. BusyBox 1.37.0 is built from upstream with musl, without Axiom64-specific source patches. The full image also imports Linux-ABI, musl-linked packages from Alpine 3.22 x86-64. Their executables run against Axiom64's syscalls.

Native development tools are GCC 14.2.0, binutils 2.44, and Make 4.4.1. Desktop packages include Xorg 21.1.19, fbdev and evdev, twm, xterm 399, xeyes, bitmap fonts, Bash 5.2.37, and zsh 5.9. Tests compile and execute new programs with the imported native toolchain.

`dependencies.json` pins the bootloader, protocol header, and BusyBox by SHA-256. `ports.lock.json` pins APK URLs, versions, SHA-256, license labels, upstream sites, origins, and source commits. Root filesystem assembly treats package contents as data and never runs installation hooks. Font indexes are generated explicitly. Mesa's renderer, LLVM, and SPIR-V payloads are omitted because the image uses fbdev with GLX disabled.

`sources.lock.json` pins exact Alpine APKBUILD recipes and their source and patch checksums. Sources come from Alpine's distfile cache or the recipe's exact repository commit and are checked with SHA-512. Recipe bodies are preserved as text and never executed by the fetcher. The lock also pins Ubuntu's source package for static programs' musl.

The image includes copyright and license notices under `/usr/share/licenses`, plus port and source manifests. Produce the companion source bundle with:

```sh
make sources
```

`build/axiom64-sources.tar` contains upstream sources, patches, recipes, manifests, the BusyBox configuration, and Axiom64 build sources. CI publishes it beside the boot artifact. Recipes describe the distribution's build options and patches; Axiom64 does not claim to reproduce every distribution binary bit for bit.

Updating ports is an explicit maintenance operation. Resolve package roots with `scripts/ports.py resolve`, refresh recipes with `scripts/sources.py resolve`, review both locks, and run the full firmware tests. Ordinary builds use committed locks. Source caches reject changed checksums; remove an outdated cached patch before fetching its new pinned revision.
