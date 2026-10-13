# GNU login-record verification reader

This directory pins the inputs used to build the static GNU libc reader in `userspace/tests/security/account-login-libc.c`. The reader opens actual utmp, wtmp and btmp files through GNU `getutxent`; the guest tests execute it inside Axiom64.

`inputs.json` records Ubuntu's GNU libc 2.39 development package, GCC 13 runtime development package, their corresponding source archives, every staged compiler/linker input, selected Linux errno headers and complete license notices. The builder verifies package identities, sizes and hashes before compilation. It uses an explicit sysroot and static link inputs, records the actual linker trace and rejects unexpected libraries. GNU libc itself comes from the pinned package; this recipe does not build a general Axiom64 glibc port.

Build a fresh verification kit with:

```sh
python3 scripts/build_gnu_utmp_reader.py --output build/gnu-reader-kit
```

The kit includes `application.c`, `application.o`, the original reader, the sysroot libraries, `relink.sh`, input/product manifests and notices. Copy the kit before changing its libraries, then run its relink script with a Linux x86-64 GNU compiler to produce a reader using those modified inputs. The unchanged kit reproduces the original reader after moving to a different directory.

`scripts/tests/gnu_utmp_reader_test.py` checks independently encoded login records, malformed-record rejection, changed dependency/notice rejection and moved-kit relinking. `make sources` includes the portable kit and complete pinned upstream archives beside the Axiom64 sources. The existing GNU libc LGPL notices and GCC runtime exception remain intact here and in the kit.
