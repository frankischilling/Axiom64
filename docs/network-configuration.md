# IPv4 configuration, DHCP, and resolver metadata

Ring 3 C++ modules implement checked IPv4 address/route installation, ownership recovery, DHCP packets and lease state, saved profiles, and owned resolver metadata. They support [#69](https://github.com/frankischilling/Axiom64/issues/69), [#67](https://github.com/frankischilling/Axiom64/issues/67), [#71](https://github.com/frankischilling/Axiom64/issues/71), and the complete DHCP/configuration task [#66](https://github.com/frankischilling/Axiom64/issues/66). The normal boot image does not yet start a network manager or read these profiles.

The planned default configures every connected Ethernet adapter with DHCP. Saved static settings take precedence for each interface; a disabled profile excludes that interface. The full release also requires DNS resolution, TCP/UDP transfers, ping, downloads, accounts, permissions, and secure randomness. These remain in the [feature roadmap](feature-roadmap.md).

## Complete address updates

The [netlink interface](netlink.md) accepts `RTM_NEWADDR` with create/exclusive flags and `RTM_DELADDR` for physical interfaces 1 through 8. `ifaddrmsg` carries IPv4 family, prefix, interface, universe scope, and either zero or permanent address flags. Checked `IFA_LOCAL` and `IFA_ADDRESS` must describe the same local address; an optional `IFA_BROADCAST` must match the prefix-derived broadcast. Addresses and masks use host order in C++ and network order in address attributes.

Validation finishes before one complete address/mask/broadcast tuple reaches `ipv4_configure`. An occupied interface returns `EEXIST`. Delete requires the exact local address and prefix and returns `EADDRNOTAVAIL` for a mismatch. Malformed or unsupported requests preserve the previous tuple. Legacy interface ioctls retain their existing behavior. There is one address per physical interface; aliases, address dumps, finite address lifetimes, IPv6, and change notifications remain required.

`ax::net::Routing::change(Address, remove)` supplies the checked request and acknowledgment exchange. It uses the same private socket, sender/port/sequence checks, positive errno results, and one-second monotonic deadline as route changes.

## Configuration ownership and recovery

`userspace/net/config/configuration.hpp` exposes `ax::net::Configuration`. `open(interface, runtimeStore)` verifies the selected interface's name, index, and MAC and recovers an earlier process's ownership record. `apply(address, parameters, metric, protocol)` installs the complete address and its routes. `withdraw()` removes recorded settings. `close()` releases descriptors and leaves synchronized ownership for the next process to recover. The runtime Store must outlive the Configuration and use a volatile filesystem such as `/run`.

The module owns only recorded address tuples and explicitly tagged routes. DHCP routes use `RTPROT_DHCP` (16); saved static routes use `RTPROT_STATIC` (4). A zero requested metric selects `100 + interface index`; explicit metrics range from 2 through 32767. Up to 24 supplied routes and a router-derived default fit one snapshot. A classless-route option suppresses the separate router option, including when the classless list is empty. On-link routes are installed before gateway routes. Gateways currently must be directly reachable on the interface's configured subnet.

Before mutation, the module checks current addresses and route collisions and synchronizes an intent containing the old and desired snapshots. It then removes old owned routes, replaces the address if needed, installs new routes, and synchronizes the committed snapshot. A failed operation attempts to restore the old tuple and routes. Failed rollback retains the intent for subsequent cleanup/recovery. These are checked operations with journaled rollback; several route messages do not form one kernel transaction.

Restart recovery removes either recorded tuple and both recorded route groups. A manually changed address that matches neither tuple survives. Unrelated routes survive protocol/scope/interface/metric-filtered removal. An existing unowned address returns `EBUSY`; an exclusive route collision returns `EEXIST`. Configuration does not publish resolver files or lease hints; the future manager must coordinate those results with successful lease installation and expiry.

Ownership uses `<interface>.owned` in the runtime directory. The record has an eight-byte `AXNWOWN1` magic, little-endian length and FNV-1a checksum, interface/MAC identity, and two snapshots. Its fixed header is 60 bytes; each route occupies 24 bytes, for at most 1260 bytes. Reads validate lengths, counts, padding, masks, broadcasts, route protocols/scopes, and interface identity before claiming ownership. Corruption returns `EINVAL`; a changed interface identity returns `ESTALE`. The checksum detects accidental corruption. Protocol tags and runtime records do not establish authorization between root processes.

## DHCP packets, state, and transport

`userspace/net/dhcp/wire.hpp` encodes discover/select/reboot/renew/rebind/decline/release/inform requests and validates BOOTP/DHCP replies against transaction, MAC, client identifier, message type, and server identity. It supports checked option concatenation/overload, subnet/router/DNS/lease/timer options, compressed search names, and classless routes. Raw frames check Ethernet addressing, IPv4 and UDP lengths/checksums, and server/client ports. Options and IPv4 fragmentation are unsupported in this raw bootstrap path.

Buffers are bounded: 1472 bytes of DHCP payload, 24 routes, three DNS addresses, 254 bytes of domain text, and 512 bytes of search text. Search compression accepts backward references only to recognized label boundaries. Invalid decoding leaves the caller's reply unchanged. ARP helpers encode probes/announcements and recognize conflicting claims while excluding the host's own interface MACs.

`Client::advance(event, monotonicMilliseconds, randomValue)` returns one owned action at a time. Completion tokens associate asynchronous results with their original action. The state module implements discovery and request retries, a saved-address reboot attempt, lease renewal/rebinding/expiry, checked ACK/NAK handling, RFC 5227 probes and announcements, conflict defense/decline backoff, carrier transitions, and release/withdraw on stop. Expiry precedes input handling; delayed installation completion cannot revive an expired or stopped client. Tests supply deterministic time/random inputs. The production manager still needs a verified source of randomness and a complete event loop.

`Transport` owns a raw Ethernet bootstrap socket, a device-bound wildcard UDP port 68, and a specific UDP socket after configuration. It uses nonblocking close-on-exec descriptors, ignores its own outgoing packet copies, and bounds receive work. Initial requests work before an IPv4 address exists; configured renewal and release use the installed source address. Transport and the state module are buildable libraries and test inputs; normal startup has not integrated them.

## Saved profiles and lease hints

`ax::net::Store` accepts an absolute directory and interface keys containing 1–15 letters, digits, hyphens, or underscores. Profiles use `<interface>.conf`; lease hints use `<interface>.lease`. A static profile has this format:

```ini
axiom64-network=1
mode=static
address=10.23.1.40
netmask=255.255.255.0
gateway=10.23.1.1
dns=10.23.1.53 10.23.1.54
domain=lab.example
search=lab.example dev.lab.example
metric=101
hostname=axiom64
route=198.51.100.0/24 0.0.0.0
```

`mode=dhcp` and `mode=disabled` accept hostname/metric and exclude static address, route, and resolver settings. Records must include the version and mode. Files are shorter than 4096 bytes; LF/CRLF, whitespace, empty lines, and full-line comments are accepted. Unknown keys, duplicate scalar fields, invalid addresses/masks/names, excessive lists, and duplicate route prefixes are rejected. Static gateways currently use the directly connected subnet.

Saved profiles and hints use the private policy in `userspace/net/config/saved.cpp`. Each directory component is opened relative to its validated parent with `O_DIRECTORY`, `O_NOFOLLOW`, and close-on-exec. After Store's trailing-slash normalization, empty, `.` and `..` components are rejected. Ancestors must belong to root or the effective UID; group/other-writable ancestors must also be sticky. The final directory must belong to the effective UID with mode 0700. Saved inputs must be regular files owned by that UID, with mode 0600 and one link. File type is checked before opening, and nonblocking/no-follow opens plus descriptor metadata checks reject a replaced input without waiting on a FIFO. Failed reads leave the complete caller output unchanged.

Writes validate the existing destination, create a mode-0600 exclusive temporary file, check every write and close, synchronize the file, rename it relative to the validated directory, and synchronize the directory. Newly created directories are restored to mode 0700 and temporary files to mode 0600 even under a restrictive umask. Existing unsafe paths are rejected rather than repaired. Hint removal applies the same private directory and file validation before unlinking. Missing hints remain safe to forget repeatedly. Configuration and resolver journals retain their separate Store contracts, including the resolver's public directory and text modes.

A lease hint contains only version, MAC, and previous address. It never preserves an old monotonic lease deadline; a changed MAC returns `ESTALE`. This saved-file policy does not replace kernel account/permission enforcement. Axiom64 currently exposes a root identity; native Linux checks exercise real foreign owners and permission denial. A process with the same effective UID remains within the trusted writer domain.

## Owned resolver metadata

`userspace/net/config/resolver.hpp` exposes `ax::net::Resolver`. `open(runtimeStore, target)` accepts a dedicated volatile Store and a resolver target, defaulting to `/etc/resolv.conf`. `update(interfaceIndex, parameters, metric)` copies only DNS/domain/search metadata into one of eight contribution slots. `withdraw(interfaceIndex)` removes that contribution. Positive errno values report failures; `managed()` reports whether automatic publication still owns the target, and `limited()` reports complete contributions omitted by the output bounds. The Store must outlive the Resolver. `close()` leaves recorded contents for restart recovery.

Contributions are ordered by lower metric, then interface index. Zero metric selects `100 + index`; explicit metrics range from 2 through 32767. Three distinct IPv4 nameservers are emitted. Search text takes precedence over a contribution's domain option. Names are lowercased, trailing dots are removed except for the root name `.`, and duplicates are removed. At most six complete search names fit a 247-character value; oversized names are omitted whole and set `limited()`. This gives a complete search line of at most 255 bytes, including its directive and newline, within the pinned musl parser's 256-byte input buffer. The total output buffer is 1024 bytes, including its terminator. The module validates every contribution before replacing stored metadata.

The generated file is `<runtime>/resolv.conf`; ownership is `<runtime>/resolv.owned`. New runtime directories use mode 0755 and resolver text uses mode 0644 so applications can read it. Ownership records remain mode 0600. Permission changes and synchronization are checked even with a restrictive umask. Existing private, foreign-owned, or group/other-writable runtime directories return `EACCES` instead of changing their access policy. The caller must select a dedicated directory under traversable parents, such as `/run/resolver`; the module does not change existing ancestor permissions.

The resolver target becomes an absolute symlink to the runtime file only when absent. A manual regular file, foreign symlink, replaced target, or edited generated contents takes precedence and switches `managed()` off. A generated comment alone does not establish ownership. Before each publication, the module checks the target policy, expected current contents, and ownership record. It synchronizes an old/new intent, atomically replaces the text, then synchronizes the committed record. Recoverable failures restore the previous output; a failed rollback retains pending old/new state for retry or restart. File replacement preserves existing open readers. These file operations do not form a transaction with address/route installation; the manager must coordinate their results.

The ownership record has eight-byte magic `AXRSLV01`, little-endian total length and FNV-1a checksum, old/new lengths, and both complete texts. Its header is 24 bytes and the maximum record is 2070 bytes. Validation checks lengths, checksum, canonical nameserver/search directives, duplicates, and line bounds before claiming ownership. Restart clears only a current file matching a recorded old or new snapshot; an unrecorded or manually changed file survives. A missing runtime file can be recreated. The checksum detects accidental corruption and does not authorize another process. A future singleton manager must serialize updates.

Opening and withdrawing all contributions leaves only the generated comment. The module publishes metadata; DNS queries, UDP/TCP fallback, search behavior, query timeouts, and coordinated normal-service startup remain required in #66/#14.

## Verification and remaining integration

```sh
make test-address-codec
make test-configuration
make build/configuration-native
sudo python3 scripts/configuration_native.py
make test-dhcp-codec
make -j2 build/profile-privacy-host build/profile-privacy-tests build/profile-privacy-dynamic
sudo python3 scripts/profile_native.py
make test-profiles
make test-dhcp-modules
make test-dhcp-transport
make test-resolver-native
make test-resolver
```

The sanitizer address test uses 16 independent fixtures and 8000 mutations against the production parser. Four mixed virtio-net/e1000 boots cover BIOS/UEFI and modern/legacy transport. Guest Configuration tests verify full tuples, exclusive creation/exact deletion, failed address creation with 32 unread replies, static/DHCP route tags, replacement, manual preservation, corrupt and stale records, failed journal publication, actual process exit, and rollback after filling the real 32-route table. Six persisted intent fixtures derive from production-written snapshots; each child exits at a distinct real kernel state during replacement, and a new Configuration cleans only the recorded settings. These tests use a volatile guest filesystem.

The native comparison runs only common address-message and Routing-adapter contracts in an isolated Linux network namespace and records its kernel version. Axiom64-specific journal recovery, single-address limits, rejection policies, and resource quotas are guest checks.

The DHCP module matrix runs codec, state, and profile programs in 12 guest boots. Host sanitizers also exercise 12000 reply mutations, deterministic lifecycle/time/conflict scenarios, and 32 atomic profile replacement cycles. The real-wire matrix runs four boots with two independent Ethernet peers. The peer drops each interface's first discovery and supplies a wrong-transaction offer before a valid offer. Each client acquires the ACK settings, sends one unicast renewal and one broadcast rebinding, installs the changed prefix/router, checks the ACK's DNS metadata, and releases/withdraws ownership. The peer checks all fields, checksums, MACs, ARP, and exact packet counts. Clients run sequentially in this module fixture.

Private saved-file checks run GNU sanitizer and static/dynamic musl programs under ordinary and root UIDs on native Linux. Real foreign owners, writerless FIFOs, socket files, mode/link violations, unsafe ancestors, symlinks, malformed/oversized inputs, restrictive umasks, and repeated rejected traversals exercise the production policy. Linker wrappers inject write, read, close, file/directory synchronization, permission, and rename failures around real files. Precommit failures preserve the old snapshot; a directory synchronization failure after rename reports an error while retaining the complete new snapshot. Eight BIOS/UEFI modern/legacy guest boots run both musl linkages on RAM and disposable ext2, plus independent ABI tests. Guest unmount, independent host fsck, and host seed-byte comparison are required. Native-only FIFO creation and foreign credentials are not claims about guest support. Musl's descriptor-relative `fchmodat` uses the Linux three-argument syscall; ABI programs separately check its path selection, symlink following, inode type, and error behavior.

Resolver checks run on native Linux with ASAN/UBSAN and in four BIOS/UEFI modern/legacy guest boots. They verify eight contributions, metric ordering, replacement/withdrawal, complete line limits, private ownership/public text permissions, manual intervention, retained readers, actual process exit, 70 corrupt-open cycles, and 20 malformed record variants. Four intent fixtures derive from production-written texts; child processes leave real old/new/committed/missing file states, and restart clears only recorded metadata. Linker wrappers inject failures at three publication renames, six file/directory synchronization points, initial link synchronization, permission changes, and a failed rollback while surrounding operations use real files. Descriptor exhaustion exercises a real `EMFILE` failure and retry with one free slot. These tests use isolated fixture directories and do not modify the host's resolver.

Evidence is under `build/configuration-*`, `build/dhcp-*`, `build/profile-*`, `build/resolver-*`, and their result JSON files; CI retains the logs/results alongside the earlier full OS/source gates. Normal manager startup, concurrent default clients, singleton/signal supervision, static conflict management, coordinated resolver updates, complete server-loss/carrier/device-error/reboot matrices, and the first usable networking release remain in #66 and the parent scopes. Publishing DNS metadata is separate from running a resolver.

Primary protocol references are [RFC 2131](https://www.rfc-editor.org/rfc/rfc2131.html), [RFC 2132](https://www.rfc-editor.org/rfc/rfc2132.html), [RFC 3396](https://www.rfc-editor.org/rfc/rfc3396.html), [RFC 3397](https://www.rfc-editor.org/rfc/rfc3397.html), [RFC 3442](https://www.rfc-editor.org/rfc/rfc3442.html), [RFC 5227](https://www.rfc-editor.org/rfc/rfc5227.html), and the pinned Linux [address definitions](https://github.com/torvalds/linux/blob/v6.12/include/uapi/linux/if_addr.h) and [IPv4 address implementation](https://github.com/torvalds/linux/blob/v6.12/net/ipv4/devinet.c).

Resolver bounds follow `src/network/resolvconf.c` and `lookup.h` in the pinned [musl 1.2.5 source](https://musl.libc.org/releases/musl-1.2.5.tar.gz); the build host's pinned [musl 1.2.4 source](https://musl.libc.org/releases/musl-1.2.4.tar.gz) has the same nameserver and line bounds. Both source archives are in the corresponding-source bundle.
