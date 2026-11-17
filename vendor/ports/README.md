# Preserved package inputs

This directory keeps exact locked package archives that are needed for reproducible
builds after their original repository URL becomes unavailable. `ports.lock.json`
declares each `vendored_archive`; the package fetcher checks that file and its
cached copy against the same pinned SHA-256 before use. A missing or changed
declared archive fails verification.

## zlib 1.3.2-r1

`zlib-1.3.2-r1.apk` is the unchanged Alpine Linux 3.22 x86-64 package already pinned
by Axiom64. It retains Alpine's package metadata and signature bytes. The archive
was preserved after its original URL returned HTTP 404 during a cold build.

| Property | Value |
| --- | --- |
| Upstream | [zlib](https://zlib.net/) |
| Original package URL | `https://dl-cdn.alpinelinux.org/alpine/v3.22/main/x86_64/zlib-1.3.2-r1.apk` |
| Archive bytes | 55,457 |
| SHA-256 | `af24e502645e2b392cae833856d776691ac21655362e5db69d7b89f147f76216` |
| Alpine recipe commit | `121fc97db0e7c59db704891b6d7ef83ae5df2cc2` |
| License | [Original zlib notice](zlib.LICENSE) |

The corresponding `APKBUILD`, `zlib-1.3.2.tar.gz` and `CVE-2026-85091.patch` remain
pinned in [`sources.lock.json`](../../sources.lock.json). The source bundle carries
them under `ports/zlib` and includes this directory under `Axiom64/vendor/ports`.
The notice is copied unchanged from `zlib-1.3.2/LICENSE` in that upstream source
archive; its SHA-256 is `e32ff4e00d9d94930537635291da39e7e612703334bf6fde8c7f1686fe8a45a2`.
