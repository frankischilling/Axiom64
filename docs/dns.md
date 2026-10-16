# IPv4 UDP and TCP name resolution

Linux ABI applications use the installed musl `getaddrinfo` resolver through the existing IPv4 UDP, poll, clock and file interfaces. The resolver reads `/etc/hosts` and `/etc/resolv.conf`; the network manager's [owned resolver module](network-configuration.md#owned-resolver-metadata) publishes nameservers and search domains. Dedicated resolver tests use private fixture files and static interface addresses. The normal-init tests also run application lookups using the installed DHCP manager's published resolver settings.

Both static and dynamic musl lookups return checked IPv4 addresses, service ports and result metadata. Tests exercise compressed CNAME records and multiple A records, local numeric/hosts precedence, search-domain order, bare-name fallback, `ndots` and absolute names. Their expected search behavior follows the pinned musl implementation. It should not be treated as a claim that every libc has identical search rules.

The resolver queries configured nameservers in parallel. The controlled peer drops a first answer, leaves one nameserver silent and exhausts refused/SERVFAIL responses. Separate one-second fixtures check retry timing and `EAI_AGAIN`; NXDOMAIN and empty successful answers produce `EAI_NONAME` and `EAI_NODATA`. First lookups allow two seconds for cold link/ARP setup. Wrong IDs, source addresses, source ports and short replies precede a delayed valid answer and must not supply a poisoned result.

The kernel provides [IPv4 TCP streams](tcp.md). A checked local musl patch validates UDP/TCP response ownership, preserves complete TCP frame boundaries and drains declared bodies beyond the pinned lookup buffer. IPv6, DNSSEC, downloads, TLS/certificate validation and the complete DNS/network release requirements remain in [TCP and UDP sockets](tcp.md) and [network configuration](network-configuration.md).

## Verification

```sh
sudo -n make test-dns-native
make test-dns
sudo -n make test-dns-tcp-native
make test-dns-tcp
```

The native comparison creates new mount and network namespaces before binding private fixture resolver/hosts files and isolated UDP listeners. It checks both namespace identities before changing mounts or addresses. The original host resolver and hosts files remain outside those namespaces.

The guest matrix uses virtio-net and e1000 together in four independent kernels: BIOS/UEFI and modern/legacy virtio. Every kernel runs both musl linkages. Each linkage checks 17 lookup cases, eight concurrent queries and 128 reclamation cycles. Results are freed, and a subsequent descriptor allocation must reuse the baseline slot after repeated resolver socket creation/closure.

Independent Ethernet peers verify DNS questions, exact query inventories and order, interface addresses, IPv4/UDP lengths and checksums, retries and complete answer bytes. A test-only packet observer records the actual kernel's incoming/outgoing frame lengths, hashes, types and monotonic clocks. Every peer frame must match a guest receipt, and both capture sockets must report zero drops. Receipts are collected in bounded memory and printed after the observer stops so console output does not delay capture during repeated lookups.

Evidence uses `build/dns-*`: native/guest results, serial logs and complete packet JSON. The network CI job retains that evidence. The existing ABI/thread/signal/VFS/compiler/desktop/input, driver/storage/ext2/root, format/sanitizer and corresponding-source checks remain required before integration. These checks establish the bounded UDP lookup behavior described above.

## TCP fallback

`getaddrinfo` starts TCP only after an owned UDP answer carries TC. The TCP query
uses the selected configured nameserver at port 53 and preserves the UDP query
bytes. Responses must match the ID, response/opcode flags and any present
QNAME/QTYPE/QCLASS. Names compare without case sensitivity and retain label
boundaries; malformed compression traversal is bounded. Unowned complete frames
are discarded while the original resolver deadline continues.

The transport reads the two-byte length and exactly the declared body before
accepting a response. Split length/body delivery, coalesced wrong-ID then valid
frames, EOF inside either part, a valid questionless 12-byte NXDOMAIN response,
refusal and an established silent peer are covered. Forty checked A records
exceed UDP's 512-byte base size. A 4,096-byte frame tests full draining; the
upstream 768-byte lookup buffer remains a provider limit. These fixtures place
their usable records within that buffer.

Eight independent kernels cover static/dynamic clients, BIOS/UEFI and
modern/legacy virtio, each with virtio-net and e1000. Each client checks 43 serial
cases, eight concurrent queries whose replies arrive in reverse order, and 128
alternating successful/failed reclamation lookups. Descriptor allocation must
reuse the baseline slot. The peer adds a measured 25 ms response delay so the
32-frame driver observer can retain each burst; concurrent TC and TCP answers
arrive 15 ms apart while all eight queries overlap. After client completion the
observer drains close traffic until 100 ms of quiet, with a two-second bound.
Neither operation changes resolver or kernel TCP deadlines.

Independent PCAP decoding checks UDP TC ownership, nameserver/adapter tuples,
checksums, exact transaction inventories, TCP sequence reassembly, every framed
byte, split/silent elapsed clocks and acknowledged close. Captured IPv4 bytes
must also match all actual driver receipts with zero drops. Synchronized damaged
PCAPs, peer records and driver receipts retain valid checksums; poisoned addresses,
IDs, queries, frame lengths, missing bodies, ACKs for unsent bytes and shortened
clocks must be rejected.

Native private namespaces run 21 socket cases against static/dynamic build musl
and the installed runtime. They retain real UDP/TCP bytes, source, clients,
interpreter copies and input/product hashes. Native glibc supplies a measured
comparison: its observed error codes and response filtering differ from musl.
A silent TCP peer remains open past the four-second glibc harness bound, so that
observation does not establish a finite glibc resolver deadline. Common successful
controls remain required. The patched musl clients must return `EAI_AGAIN` within
the configured one-second wait and must never return a poisoned address.

CI retains `build/dns-tcp-*` reports, raw PCAPs, serial logs, synchronized negative
fixtures, provider manifests and both exact boot images. Corresponding sources
include the original archives, distribution patches and ordered local patch.
The complete CI and existing UDP, normal DHCP DNS and TCP lifetime gates remain
required before integration.

## Normal DHCP-to-query path

`make test-normal-manager` retains all 32 existing normal-init cases across BIOS/UEFI, modern/legacy virtio, RAM/ext2 roots and no-NIC/no-server/missing/healthy scenarios. The real PID1 starts the installed manager alongside the desktop and console. Both static and dynamic musl applications query an absolute controlled name after the initial lease and again after PID1 reaps and restarts the manager. They read the unchanged `/etc/resolv.conf` target and do not set interface addresses or resolver files.

The peer accepts queries only at each healthy adapter's current ACK nameserver. Initial and restarted leases publish different nameservers, and each lookup must return its phase-specific A address and numeric port 80 with IPv4 stream-service metadata. This checks resolver output; it does not establish a TCP connection. Complete Ethernet/IP/UDP/DNS bytes, checksums, routes, query order and fresh neighbor resolution are retained in `build/normal-init-login-*/normal-init-*-dns-packets.json`. With two accepted leases, both nameservers receive queries and one remains silent. A missing DHCP peer contributes no nameserver. No-NIC/no-server controls skip application DNS because they have no accepted lease.

The original singleton/profile/hint/journal, signal/reaping/backoff, same-desktop/window/input and persistent-root filesystem checks remain required. Application binaries and peer controls are added only to private test fixtures; installed kernel/init/manager programs keep their production implementation. The normal-path checks exercise DHCP-to-DNS configuration and bounded libc TCP fallback. Downloads, TLS and the complete networking release still need acceptance.

The wire format follows [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035.html); response ownership and TCP framing follow [RFC 7766 sections 7–8](https://www.rfc-editor.org/rfc/rfc7766.html#section-7). Resolver behavior comes from the pinned [musl name lookup](https://git.musl-libc.org/cgit/musl/tree/src/network/lookup_name.c?h=v1.2.5), [configuration parser](https://git.musl-libc.org/cgit/musl/tree/src/network/resolvconf.c?h=v1.2.5) and [query transport](https://git.musl-libc.org/cgit/musl/tree/src/network/res_msend.c?h=v1.2.5), plus the ordered local patch, all included in the corresponding-source bundle.
