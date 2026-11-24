# Link inventories and IP control over netlink

Ring 3 programs can inspect, add, and remove the supported IPv4 routes through `AF_NETLINK` with `NETLINK_ROUTE`. Routes retain their Linux protocol and scope, allowing the network configuration adapter to remove an owned on-link route while preserving an unrelated gateway route. The [network manager](network-manager.md) uses this interface for DHCP configuration. [Initial IPv6 control](ipv6.md) adds explicit permanent addresses, DAD flags, main-table routes and family-aware inventories. The complete routing interface remains unfinished.

## Messages and routes

| Operation | Supported contract |
| --- | --- |
| `RTM_GETLINK` | Multipart link inventory for unspecified, IPv4, IPv6, or packet family; physical interfaces and loopback, with name, flags, MTU, hardware/broadcast address, operational state, and software transmit queue length |
| `RTM_NEWLINK`, `RTM_SETLINK` | Change administrative state and MTU on an existing Ethernet adapter with `CAP_NET_ADMIN`. A link change may set both fields in one request. IPv6 address-generation mode uses a separate request. |
| `RTM_GETADDR` | Multipart IPv4/IPv6 address inventory selected by family and, with strict checking enabled, interface index. Reports flags and cache information, plus IPv4 labels, local and peer addresses, and optional broadcast data, or IPv6 prefix and scope. |
| `RTM_NEWROUTE` | Main-table unicast supports create with exclusive or append. IPv4 also supports create alone and accepts a local preferred source. IPv6 requires an explicit interface. IPv4 gateway routes can infer it from a configured subnet. |
| `RTM_DELROUTE` | Matching destination/prefix with optional interface, gateway, priority, protocol, and scope filters. IPv4 also accepts a preferred source filter. |
| `RTM_GETROUTE` | Multipart dump with `NLM_F_DUMP`; IPv4 or unspecified family, optional protocol/interface filters; main-table unicast records followed by `NLMSG_DONE` and status |
| `RTM_NEWADDR` | Insert an IPv4 local address, prefix, label, optional broadcast and lifetimes on an explicit physical interface; replace refreshes existing lifetimes without changing its identity |
| `RTM_DELADDR` | Delete a matching address/label; a supplied peer also requires its exact prefix; a mismatch returns `EADDRNOTAVAIL` |

Attributes are checked, aligned, four-byte scalars: `RTA_DST`, `RTA_GATEWAY`, `RTA_PRIORITY`, `RTA_OIF`, and `RTA_TABLE`. Address attributes use network byte order; interface, priority, and table use native byte order. Unknown or duplicate attributes, invalid lengths, noncanonical prefixes, and unsupported families, tables, flags, types, and operations return errors before changing that request's route. Dumps accept only interface/table attributes as filters. Route inventories also report `RTA_PREFSRC` for address-derived prefixes; preferred-source mutation remains required.

The main table has 32 explicit slots, up to 32 automatic Ethernet prefixes and the fixed loopback subnet. Automatic entries report `RTPROT_KERNEL` and `RT_SCOPE_LINK`. Deleting one leaves its local address assigned and available for binding. Unchanged address configuration does not restore it; explicit recreation, address reassignment or an interface down/up cycle can restore the prefix. Administrative down removes that interface's routes. Reactivation restores automatic prefixes; manual routes must be added again. Removing an interface's final IPv4 address also removes its routes.

New on-link routes require link scope; gateway routes require universe scope. An explicitly indexed direct route can be installed before the Ethernet interface has an IPv4 address, including while physical carrier is absent. Address assignment retains its protocol, scope and metric. Fresh output on an administratively down interface returns `ENETUNREACH`; the current physical-carrier guard returns `ENETDOWN`. A device-bound raw or UDP description can select another interface's source address, or zero when none exists. Unbound selection through an unconfigured direct route still needs Linux compatibility work. An omitted interface can only be inferred from a configured subnet. A gateway must currently be a nonlocal unicast address on the selected interface's configured subnet. Address messages complement the existing [IPv4 ioctls](ipv4.md#configuration-and-routing); the complete tuple and [ownership/recovery contract](network-configuration.md) avoid intermediate address/netmask changes. [IPv4 routing](ipv4.md) describes the corresponding packet behavior.

Address mutation requests validate the eight-byte `ifaddrmsg`, universe scope, permanent/deprecated/secondary flags, and aligned `IFA_LOCAL`, `IFA_ADDRESS`, `IFA_LABEL`, `IFA_BROADCAST`, `IFA_CACHEINFO` and `IFA_FLAGS` attributes. The kernel derives the stored state flags from the address and lifetimes. Labels need not match the indexed device name; an omitted label uses that name. New local and address values must agree; deletion also accepts `IFA_LOCAL` without a peer attribute, in which case its prefix does not constrain the match. An explicit broadcast is retained as supplied; an omitted broadcast stays zero. Attribute addresses use network byte order and the interface index uses native byte order. The inventory holds at most 32 Ethernet addresses across the physical interfaces. Same-prefix additions become secondary addresses. By default, removing or expiring a primary removes those secondaries; configurable promotion preserves them. Invalid requests preserve the inventory. [Finite address lifetime development](ipv4.md#finite-address-lifetime-development) records replacement, cache information, promotion and current validation limits. Notifications remain required.

Link and address dumps accept complete zero-filter headers. With strict checking disabled, all three supported dump types also accept the legacy family-only `rtgenmsg` request used by BusyBox. Its alignment padding is ignored, as on Linux; padding bytes are not filter fields. Strict checking requires the complete header. Unsupported filters, attributes, and families fail before a reply is published. Link inventories contain at most eight physical interfaces and loopback. Address inventories retain every assigned label plus fixed loopback, followed by checked multipart completion. Compile-time size bounds keep the complete address and route inventories within the existing reply reservation. The software transmit queue length is zero because output goes directly to bounded driver descriptors; `SIOCGIFTXQLEN` reports that same value.

Create/exclusive rejects an existing destination/prefix with the same priority, including a connected route at priority zero. Create without exclusive permits distinct next-hop/protocol aliases and rejects an identical route. Existing route ioctls retain their earlier behavior and report `RTPROT_BOOT` in dumps. Delete's zero gateway/priority/interface/protocol and nowhere scope are wildcard filters; callers managing ownership should supply explicit filters. Protocol tags describe routes and do not establish a security boundary between root processes.

IPv4 create/append adds a route after earlier equal-priority aliases. `RTA_PREFSRC` is optional and must identify a local address when it is nonzero. New unbound output through that route uses this address. Explicitly selected socket sources still take precedence. Removing the last assignment of a preferred source withdraws the routes that specify it.

IPv6 create/append accepts distinct interfaces or gateways at the same prefix and metric. A duplicate next hop returns `EEXIST`. Equal-priority routes with the same preference keep their insertion order when selecting a next hop. Removing a route by its gateway leaves the other route available. Multipath route attributes remain unsupported.

Replies carry the request sequence, the socket's authoritative port identity, and kernel sender address. Errors use `NLMSG_ERROR` with negative errno and the original request. `NETLINK_CAP_ACK` bounds the echo to its header; uncapped errors include the original payload with zero alignment padding. Successful requested acknowledgments contain a capped header echo. A dump's records and completion are queued as one owned datagram. Each request in a batch has its own result; a batch is not a route transaction.

## Socket ownership and bounds

IPv6 mutations support explicit permanent addresses on physical interfaces and main-table unicast routes. Addresses run DAD unless `IFA_F_NODAD` is requested. `IFA_F_NOPREFIXROUTE` creates no prefix route; a previously owned prefix may remain for explicit cleanup after its addresses are removed. Tentative and permanently failed addresses retain existing prefix routes. Route creation requires `NLM_F_CREATE|NLM_F_EXCL`; it rejects local gateways and global next hops without a direct route on the selected interface. Omitted or zero deletion priority is a wildcard. Route control accepts destination, gateway, interface and priority attributes; dumps can filter by protocol and interface. Finite lifetimes, replacement, automatic configuration, additional tables and complete Linux control equivalence remain unfinished. See [IPv6 development](ipv6.md) for host behavior and validation limits.

`SOCK_RAW` and `SOCK_DGRAM` accept nonblocking and close-on-exec flags. Bind allocates a unique port when the requested port is zero; connect and unconnected sends target kernel port zero. Name queries use Linux `sockaddr_nl`. Groups, peer-process delivery, subscriptions, and notifications are unsupported.

There are at most 64 socket descriptions. A socket owns at most 32 reply datagrams and 65536 reserved reply-payload bytes, plus per-frame metadata and allocator overhead. Requests are limited to 4096 bytes and 32 messages per send. Every response allocation is reserved before any request in that send is applied; allocation failure or backpressure leaves those routes unchanged. Link, single-family address and IPv4 route dumps reserve 4176 bytes even when their actual records are shorter, preserving their 15-unread-dump limit. A combined unspecified-family address dump reserves 4412 bytes for all 33 IPv4 and 17 IPv6 records, their cache information and multipart completion; its reservation permits 14 unread dumps. IPv6 route dumps reserve 6144 bytes; a combined unspecified-family route dump reserves 12288 bytes. The IPv4 route bound includes all 65 records, their preferred-source metadata and multipart completion. Consuming a reply or final close releases its reservation.

Descriptor reads/writes, vectors, and message calls share the [retained I/O path](io.md). A blocked send retains its original description, destination, vectors, and complete payload through descriptor reuse. Dup and fork preserve port identity and queued replies until final close. Receive supports nonblocking, peek, and truncation; a zero-length descriptor read retains the datagram, while a zero-length receive consumes it. A non-peek receive copy fault consumes the selected datagram; a failed peek retains it. `recvmsg` reports kernel sender metadata and zero control length.

Poll and epoll report read availability and capacity for a minimum acknowledgment. Write readiness does not promise space for every larger request or dump. `SO_TYPE`, `SO_DOMAIN`, `SO_PROTOCOL`, `SO_ERROR`, fixed buffer-size queries, `NETLINK_CAP_ACK`, and `NETLINK_GET_STRICT_CHK` are supported. Route/address mutations retain complete validation independently of the strict dump option. Other options, socket deadlines, multicast, address lifetimes, link mutations over netlink, lookup requests without dump flags, replacement, multiple tables, complete IPv6 control, policy routing, and general Linux netlink behavior remain required.

## Input device events

`AF_NETLINK` protocol `NETLINK_KOBJECT_UEVENT` exposes kernel input-device
additions on multicast group 1. A device manager with `CAP_NET_ADMIN` can
send processed events to group 2 and pass work to another event socket
by port ID. With `SO_PASSCRED` enabled, `recvmsg` returns the credentials
captured by the kernel when the datagram was sent. Listeners can adjust
their receive buffer and independently join or leave either group. If a
listener loses a multicast event because its queue is full, it receives
`ENOBUFS`. Route sockets and their port IDs remain independent.

Write `add` to a present evdev device's `/sys/class/input/eventN/uevent`
to request a coldplug event. The file uses normal owner write permissions.
Group 1 is reserved for the kernel. Other device actions and ancillary
credentials supplied by the sender are unsupported.
The [Linux uevent implementation](https://github.com/torvalds/linux/blob/v6.12/lib/kobject_uevent.c)
defines the datagram and coldplug format.

## Ring 3 configuration adapter

`userspace/net/config/routing.hpp` exposes `ax::net::Routing` behind a private nonblocking kernel-port socket. Route `change` requires a canonical mask, explicit interface, nonzero priority/protocol, and the appropriate link/universe scope. The adapter retains preferred-source and TOS fields when reading routes; host comparisons use them to distinguish independent owners. The guest still rejects preferred-source and TOS route mutations. Address `change` requires the complete canonical tuple and explicit interface. These checks prevent accidental wildcard deletion. Results are positive errno values; requests require a checked acknowledgment within a one-second monotonic deadline.

`list` returns at most 65 route records and can filter by interface/protocol. It verifies kernel sender, sequence, port identity, record bounds, and multipart completion. Failure leaves the caller's records and count unchanged. It drains an undersized result before returning `ENOSPC`; malformed, timed-out, or interrupted exchanges discard the private socket. The caller can reopen it for later work. The [Configuration module](network-configuration.md) uses this adapter for DHCP/static tuple and route ownership. Normal startup supervises the [network manager](network-manager.md) as a Ring 3 child.

## Generic netlink discovery

`NETLINK_GENERIC` and `NETLINK_ROUTE` have separate port namespaces. The
generic control family `nlctrl` answers `CTRL_CMD_GETFAMILY` by name or ID
and supports a multipart family dump. It publishes its version, discovery
operation and notification group. A lookup for an absent family returns
`ENOENT`. Unicast replies carry the kernel source address. A requested
acknowledgment follows the family reply as a separate datagram.

Both protocols support `SO_PASSCRED` for kernel sender credentials and
bounded `SO_SNDBUF` and `SO_RCVBUF` settings. Requests are capped at 512 KiB
before doubling. The receive queue still holds at most 32 datagrams. Group
membership can be set at bind time or changed with
`NETLINK_ADD_MEMBERSHIP` and `NETLINK_DROP_MEMBERSHIP`. Route sockets
subscribed to `RTNLGRP_LINK` receive kernel `RTM_NEWLINK` messages when
administrative state, MTU or physical carrier changes. A full queue
reports `ENOBUFS` so the listener can refresh its inventory. Subscribers
to `RTNLGRP_IPV6_IFADDR` receive `RTM_NEWADDR` when an IPv6 address
becomes usable after duplicate-address detection or changes flags or
lifetimes. `RTM_DELADDR` reports explicit removal and expiry.
`RTNLGRP_IPV4_IFADDR` reports additions, lifetime and flag updates, and
removals. IPv4 events carry the same address fields as a dump. IPv6 route
notifications still need support. Subscribers to
`RTNLGRP_IPV4_ROUTE` receive `RTM_NEWROUTE` and `RTM_DELROUTE` for main-table
routes added or removed through configuration or address and link changes.
`SIOCETHTOOL` returns the
bound Ethernet driver and PCI address with `ETHTOOL_GDRVINFO` and
reports link state with `ETHTOOL_GLINK`.

NetworkManager activates Ethernet with DHCPv4 and IPv6 router discovery in installed guests. Wi-Fi and the Plasma applet still need validation.

The route test also checks discovery, the missing-family error, multipart
completion, port reuse across protocols, and kernel credentials. Run the
discovery checks on Linux with `make build/netlink-native` followed by
`build/netlink-native --generic-only`. In QEMU it also checks link
changes, rejection of an invalid MTU, orderly multicast delivery after
overflow, driver identity and carrier state before and after QMP
restores both links.

## Device discovery

Network interfaces have entries under `/sys/class/net`. Ethernet entries
point to the interface under its PCI device. They publish the same
interface index and PCI location reported by socket queries. Loopback
appears under `/sys/devices/virtual/net`.

The kernel announces network interfaces on the kernel device-event
group. A privileged coldplug request to the interface's `uevent` file
repeats the add event. Its properties include the interface name and
index. The installed udev startup triggers network discovery alongside
input discovery, so the network manager can process devices present
before userspace starts.

## Verification

```sh
make test-netlink-codec
python3 scripts/tests/netlink_peer_test.py
make test-netlink
make test-address-codec
make test-netlink-inventory-codec
make test-netlink-inventory
sudo make test-netlink-inventory-native
make test-configuration
make build/netlink-native
sudo python3 scripts/netlink_native.py
```

The sanitizer test uses independent route-message fixtures and 20000 bounded mutations of valid route/dump requests. The guest matrix runs four boots: BIOS/UEFI and modern/legacy virtio, with virtio-net and e1000 together. Both carriers start down. Before either address is assigned, real route requests install independent direct routes, reject exclusive duplicates and mismatched deletion filters, and preserve exact dump metadata. Atomic address assignment retains those routes. Explicit deletion is checked before a separate recreation and final-address withdrawal prove automatic retirement. Unconfigured gateways and omitted-interface inference remain rejected. Device-bound UDP output on these disconnected links returns `ENETDOWN`, including when fallback source selection chooses another address or zero. Complete Linux carrier-loss output semantics remain required. Actual guest carrier flags gate these checks; QMP restores the links only after they pass. Each boot also checks automatic-prefix deletion, local binding, failed fresh routing, unchanged configuration, recreation, address reassignment and administrative down/up. The existing protocol/scope ownership, dump, legacy alias, unsupported-message, 32-route, 64-socket, packet-count and reserved-byte pressure, vector, copy-fault, epoll, fork/dup, and blocked-writer checks remain required.

The separate inventory codec checks all nine records, strict/legacy requests,
caller-buffer canaries, 15 valid forms, and 16000 bounded mutations. The actual
BusyBox `ip` sequence lists links, raises an interface, assigns and lists an
address, infers a default gateway route, lists and removes it, then removes
the address. A separate raw client compares every inventory with ioctl
observations before configuration, after configuration, and after withdrawal.
Static/dynamic musl, BIOS/UEFI, and modern/legacy virtio produce eight guest
cases, with 30 raw dumps per case. Three native libc profiles run the same
BusyBox sequence in isolated Linux network namespaces.

Each boot exchanges six routed UDP packets with two independent Ethernet peers. The peers verify checksums, ports, payload, IP destination/source, and ARP next hop for default, on-link, and preserved unowned gateway routes. The fixture disables IPv6 before the client starts. Firmware traffic is separated by the Ring 3 readiness marker, and the peer still rejects unexpected protocols. Evidence in `build/netlink-wire/` includes the reopened boot-image audit, source and executable hashes, logs, two packet captures per boot, and actual firmware and adapter observations. A captured automatic DAD frame remains a negative replay fixture.

The native comparison creates two veth pairs in a private Linux network namespace and leaves both peers down. It waits for actual carrier loss, compares direct-route insertion before an address, atomic address assignment, duplicate rejection, filtered dumps, explicit deletion and retirement after final-address withdrawal. The same client checks automatic-prefix and administrative lifecycle behavior before completing the earlier common message, lifetime, route ownership and adapter checks. Host interfaces/routes stay outside the namespace; `build/netlink-native-results.json` records the tested Linux kernel. Axiom64-specific quotas and rejection policies are tested separately in the guest. CI runs both comparisons alongside the earlier networking, full userspace/thread, storage, desktop, ext2-root, formatting, and corresponding-source gates.

Interface references are the pinned [Linux netlink headers](https://github.com/torvalds/linux/blob/v6.12/include/uapi/linux/netlink.h), [route headers](https://github.com/torvalds/linux/blob/v6.12/include/uapi/linux/rtnetlink.h), [IPv4 route control](https://github.com/torvalds/linux/blob/v6.12/net/ipv4/fib_frontend.c), [direct nexthop validation](https://github.com/torvalds/linux/blob/v6.12/net/ipv4/fib_semantics.c), and [netlink socket implementation](https://github.com/torvalds/linux/blob/v6.12/net/netlink/af_netlink.c). These define the broader Linux interface; the implementation supports the subset described above.
