# Normal-init fixture archive compression

[Issue #141](https://github.com/frankischilling/Axiom64/issues/141), a child of [#133](https://github.com/frankischilling/Axiom64/issues/133), tracks normal-init fixture packaging. The successful [TCG baseline](https://github.com/frankischilling/Axiom64/actions/runs/38059241982) spent 90 seconds uploading BIOS fixtures and 96 seconds uploading UEFI fixtures. Each set includes both boot images and every saved ext2 root disk.

The existing complete published BIOS set contains 10 files and 6,221,539,328 input bytes. A local ZIP benchmark checks every extracted file against its original SHA-256 and compares the same files at two compression levels:

| Compression | CPU seconds | Wall seconds | Archive bytes |
| --- | ---: | ---: | ---: |
| Existing level 6 | 134.286 | 232.209 | 997,395,920 |
| Level 1 | 62.494 | 160.776 | 1,113,190,962 |

Level 1 used 53.5% less CPU and finished 30.8% sooner in this local run, with an 11.6% larger archive. These results isolate packaging cost; hosted transfer times and runner load still require measurement. The [pinned upload action](https://github.com/actions/upload-artifact/blob/ea165f8d65b6e75b540449e92b4886f43607fa02/README.md#altering-compressions-level-speed-v-size) supports the compression setting and defaults to level 6.

The proposed workflow uses level 1 only for the normal-init root fixtures. It retains artifact names, paths, both images, all eight disks per firmware, failure evidence, every VM/native acceptance step and default TCG. Compression does not change the extracted ISO or filesystem bytes. Complete final CI, exact published source/product checks, all sixteen host filesystem checks and actual before/after hosted upload measurements remain required before adoption. This work does not establish a faster emulator policy or VM/HP readiness.
