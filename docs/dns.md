# IPv4 UDP name resolution

Linux ABI applications use the installed musl `getaddrinfo` resolver through the existing IPv4 UDP, poll, clock and file interfaces. The resolver reads `/etc/hosts` and `/etc/resolv.conf`; the network manager's [owned resolver module](network-configuration.md#owned-resolver-metadata) publishes nameservers and search domains. Dedicated resolver tests use private fixture files and static interface addresses. The normal-init tests also run application lookups using the installed DHCP manager's published resolver settings.

Both static and dynamic musl lookups return checked IPv4 addresses, service ports and result metadata. Tests exercise compressed CNAME records and multiple A records, local numeric/hosts precedence, search-domain order, bare-name fallback, `ndots` and absolute names. Their expected search behavior follows the pinned musl implementation. It should not be treated as a claim that every libc has identical search rules.

The resolver queries configured nameservers in parallel. The controlled peer drops a first answer, leaves one nameserver silent and exhausts refused/SERVFAIL responses. Separate one-second fixtures check retry timing and `EAI_AGAIN`; NXDOMAIN and empty successful answers produce `EAI_NONAME` and `EAI_NODATA`. First lookups allow two seconds for cold link/ARP setup. Wrong IDs, source addresses, source ports and short replies precede a delayed valid answer and must not supply a poisoned result.

TCP fallback, IPv6, DNSSEC and the complete DNS/network release requirements remain in [#13](https://github.com/frankischilling/Axiom64/issues/13) and [#14](https://github.com/frankischilling/Axiom64/issues/14). In particular, a truncated UDP reply requires TCP, which the kernel still needs to implement. Verified UDP resolution does not establish working downloads, TLS/certificate validation or an exposed-network security contract.

## Verification

```sh
sudo -n make test-dns-native
make test-dns
```

The native comparison creates new mount and network namespaces before binding private fixture resolver/hosts files and isolated UDP listeners. It checks both namespace identities before changing mounts or addresses. The original host resolver and hosts files remain outside those namespaces.

The guest matrix uses virtio-net and e1000 together in four independent kernels: BIOS/UEFI and modern/legacy virtio. Every kernel runs both musl linkages. Each linkage checks 17 lookup cases, eight concurrent queries and 128 reclamation cycles. Results are freed, and a subsequent descriptor allocation must reuse the baseline slot after repeated resolver socket creation/closure.

Independent Ethernet peers verify DNS questions, exact query inventories and order, interface addresses, IPv4/UDP lengths and checksums, retries and complete answer bytes. A test-only packet observer records the actual kernel's incoming/outgoing frame lengths, hashes, types and monotonic clocks. Every peer frame must match a guest receipt, and both capture sockets must report zero drops. Receipts are collected in bounded memory and printed after the observer stops so console output does not delay capture during repeated lookups.

Evidence uses `build/dns-*`: native/guest results, serial logs and complete packet JSON. The network CI job retains that evidence. The existing ABI/thread/signal/VFS/compiler/desktop/input, driver/storage/ext2/root, format/sanitizer and corresponding-source checks remain required before integration. The bounded acceptance child is [#104](https://github.com/frankischilling/Axiom64/issues/104).

## Normal DHCP-to-query path

`make test-normal-manager` retains all 32 existing normal-init cases across BIOS/UEFI, modern/legacy virtio, RAM/ext2 roots and no-NIC/no-server/missing/healthy scenarios. The real PID1 starts the installed manager alongside the desktop and console. Both static and dynamic musl applications query an absolute controlled name after the initial lease and again after PID1 reaps and restarts the manager. They read the unchanged `/etc/resolv.conf` target and do not set interface addresses or resolver files.

The peer accepts queries only at each healthy adapter's current ACK nameserver. Initial and restarted leases publish different nameservers, and each lookup must return its phase-specific A address and numeric port 80 with IPv4 stream-service metadata. This checks resolver output; it does not establish a TCP connection. Complete Ethernet/IP/UDP/DNS bytes, checksums, routes, query order and fresh neighbor resolution are retained in `build/normal-init-*-dns-packets.json`. With two accepted leases, both nameservers receive queries and one remains silent. A missing DHCP peer contributes no nameserver. No-NIC/no-server controls skip application DNS because they have no accepted lease.

The original singleton/profile/hint/journal, signal/reaping/backoff, same-desktop/window/input and persistent-root filesystem checks remain required. Application binaries and peer controls are added only to private test fixtures; installed kernel/init/manager programs keep their production implementation. The normal-path acceptance child is [#106](https://github.com/frankischilling/Axiom64/issues/106). TCP fallback, downloads/TLS and the complete networking release remain in the full parents.

The wire format follows [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035.html). Resolver behavior comes from the pinned [musl name lookup](https://git.musl-libc.org/cgit/musl/tree/src/network/lookup_name.c?h=v1.2.5), [configuration parser](https://git.musl-libc.org/cgit/musl/tree/src/network/resolvconf.c?h=v1.2.5) and [query transport](https://git.musl-libc.org/cgit/musl/tree/src/network/res_msend.c?h=v1.2.5), included in the corresponding-source bundle.
