# Local musl patches

The source lock pins Ubuntu musl 1.2.4-2 for build-time programs and Alpine musl
1.2.5-r12 for the installed runtime and native development libraries. The original
archives, distribution recipes and patches remain pinned and bundled. Local
patches apply afterward, in `sources.lock.json` order, with checked SHA-256 hashes
and no patch fuzz.

The DNS transport patch checks response identifiers, response flags and present
questions, preserving label boundaries, case-insensitive names and bounded
compression traversal. TCP reads consume exactly one framed response, discard
unowned frames within the original deadline and wait for the entire declared body
before accepting a bounded answer. The upstream lookup buffer limit remains.

`scripts/build_musl.py` builds each provider with its own headers and startup
objects. It retains upstream notices, a build/input/product manifest and the
patched transport source under `build/musl`. The host toolchain and resolver files
remain unchanged. Existing guest fixtures use the patched build-provider
interpreter; the TCP DNS fixtures use the patched installed-runtime interpreter.
The normal image also replaces the installed runtime, native headers and static libc.

For an individual host-built client, `python3 scripts/musl_cc.py -static app.c -o app`
selects the same checked provider. Make regenerates compiler specs for the current
workspace before using cached libraries or linking programs.

The patch retains musl's MIT license. Original copyright notices remain in the
source archives, source bundle and installed license directory. Kernel code is
covered by the repository license.
