# IPv4 route and address control over netlink

Ring 3 programs can inspect, add, and remove the supported IPv4 routes through `AF_NETLINK` with `NETLINK_ROUTE`. Routes retain their Linux protocol and scope, allowing the network configuration adapter to remove an owned on-link route while preserving an unrelated gateway route. This implements the route-control prerequisite tracked by [#67](https://github.com/frankischilling/Axiom64/issues/67). The DHCP service and full routing interface remain in [#66](https://github.com/frankischilling/Axiom64/issues/66) and [#13](https://github.com/frankischilling/Axiom64/issues/13).

## Messages and routes

| Operation | Supported contract |
| --- | --- |
| `RTM_NEWROUTE` | `NLM_F_REQUEST`, `NLM_F_CREATE`, and `NLM_F_EXCL`; optional `NLM_F_ACK`; IPv4 main-table unicast with an explicit physical interface and canonical destination/prefix |
| `RTM_DELROUTE` | Matching destination/prefix with optional interface, gateway, priority, protocol, and scope filters; optional acknowledgment |
| `RTM_GETROUTE` | Multipart dump with `NLM_F_DUMP`; IPv4 or unspecified family, optional protocol/interface filters; main-table unicast records followed by `NLMSG_DONE` and status |
| `RTM_NEWADDR` | Create/exclusive IPv4 local address, prefix, and derived broadcast in one checked tuple on an explicit physical interface |
| `RTM_DELADDR` | Delete an exact local address/prefix; a mismatch returns `EADDRNOTAVAIL` |

Attributes are checked, aligned, four-byte scalars: `RTA_DST`, `RTA_GATEWAY`, `RTA_PRIORITY`, `RTA_OIF`, and `RTA_TABLE`. Address attributes use network byte order; interface, priority, and table use native byte order. Unknown or duplicate attributes, invalid lengths, noncanonical prefixes, and unsupported families, tables, flags, types, and operations return errors before changing that request's route. Dumps accept only interface/table attributes as filters.

The route table has 32 explicit entries, plus the configured Ethernet subnets and fixed loopback subnet. Connected entries report `RTPROT_KERNEL` and `RT_SCOPE_LINK`; they are derived from interface configuration and cannot be deleted through this interface. New on-link routes require link scope; gateway routes require universe scope. An explicitly indexed direct route can be installed before the Ethernet interface has an IPv4 address, including while physical carrier is absent. It retains its protocol, scope and metric across address assignment and withdrawal, until explicitly deleted. Packet transmission still requires a configured source address and an operational interface. An omitted interface can only be inferred from a configured subnet. A gateway must currently be a nonlocal unicast address on the selected interface's configured subnet. Address messages complement the existing [IPv4 ioctls](ipv4.md#configuration-and-routing); the complete tuple and [ownership/recovery contract](network-configuration.md) avoid intermediate address/netmask changes. The direct-route prerequisite is tracked by [#93](https://github.com/frankischilling/Axiom64/issues/93).

Address requests validate the eight-byte `ifaddrmsg`, universe scope, zero/permanent flags, and aligned `IFA_LOCAL`, `IFA_ADDRESS`, and optional `IFA_BROADCAST` attributes. Local and address must agree; the broadcast must match the supplied prefix. Attribute addresses use network byte order and the interface index uses native byte order. Physical interfaces retain one address each. Validation precedes one backend update; unsupported aliases, address dumps/lifetimes, and notifications remain required.

Create/exclusive rejects an existing destination/prefix with the same priority, including a connected route at priority zero. Existing route ioctls retain their earlier behavior and report `RTPROT_BOOT` in dumps. Delete's zero gateway/priority/interface/protocol and nowhere scope are wildcard filters; callers managing ownership should supply explicit filters. Protocol tags describe routes and do not establish a security boundary between root processes.

Replies carry the request sequence, the socket's authoritative port identity, and kernel sender address. Errors use `NLMSG_ERROR` with negative errno and the original request. `NETLINK_CAP_ACK` bounds the echo to its header; uncapped errors include the original payload with zero alignment padding. Successful requested acknowledgments contain a capped header echo. A dump's records and completion are queued as one owned datagram. Each request in a batch has its own result; a batch is not a route transaction.

## Socket ownership and bounds

`SOCK_RAW` and `SOCK_DGRAM` accept nonblocking and close-on-exec flags. Bind allocates a unique port when the requested port is zero; connect and unconnected sends target kernel port zero. Name queries use Linux `sockaddr_nl`. Groups, peer-process delivery, subscriptions, and notifications are unsupported.

There are at most 64 socket descriptions. A socket owns at most 32 reply datagrams and 65536 reserved reply-payload bytes, plus per-frame metadata and allocator overhead. Requests are limited to 4096 bytes and 32 messages per send. Every response allocation is reserved before any request in that send is applied; allocation failure or backpressure leaves those routes unchanged. Dumps reserve their maximum 4116-byte reply space even when their actual records are shorter, so 15 unread dumps exhaust the dump-sized capacity before the datagram count limit. Consuming a reply or final close releases its reservation.

Descriptor reads/writes, vectors, and message calls share the [retained I/O path](io.md). A blocked send retains its original description, destination, vectors, and complete payload through descriptor reuse. Dup and fork preserve port identity and queued replies until final close. Receive supports nonblocking, peek, and truncation; a zero-length descriptor read retains the datagram, while a zero-length receive consumes it. A non-peek receive copy fault consumes the selected datagram; a failed peek retains it. `recvmsg` reports kernel sender metadata and zero control length.

Poll and epoll report read availability and capacity for a minimum acknowledgment. Write readiness does not promise space for every larger request or dump. `SO_TYPE`, `SO_DOMAIN`, `SO_PROTOCOL`, `SO_ERROR`, fixed buffer-size queries, `NETLINK_CAP_ACK`, and `NETLINK_GET_STRICT_CHK` are supported. The supported route/address subset always validates requests strictly, including when the strict-check option is disabled. Other options, socket deadlines, multicast, address dumps/lifetimes and link messages, lookup requests without dump flags, replacement, multiple tables, IPv6, policy routing, and general Linux netlink behavior remain required.

## Ring 3 configuration adapter

`userspace/net/config/routing.hpp` exposes `ax::net::Routing` behind a private nonblocking kernel-port socket. Route `change` requires a canonical mask, explicit interface, nonzero priority/protocol, and the appropriate link/universe scope. Address `change` requires the complete canonical tuple and explicit interface. These checks prevent accidental wildcard deletion. Results are positive errno values; requests require a checked acknowledgment within a one-second monotonic deadline.

`list` returns at most 64 owned route records and can filter by interface/protocol. It verifies kernel sender, sequence, port identity, record bounds, and multipart completion. Failure leaves the caller's records and count unchanged. It drains an undersized result before returning `ENOSPC`; malformed, timed-out, or interrupted exchanges discard the private socket. The caller can reopen it for later work. The [Configuration module](network-configuration.md) uses this adapter for DHCP/static tuple and route ownership. Normal startup supervises the [network manager](network-manager.md) as a Ring 3 child.

## Verification

```sh
make test-netlink-codec
make test-netlink
make test-address-codec
make test-configuration
make build/netlink-native
sudo python3 scripts/netlink_native.py
```

The sanitizer test uses independent route-message fixtures and 20000 bounded mutations of valid route/dump requests. The guest matrix runs four boots: BIOS/UEFI and modern/legacy virtio, with virtio-net and e1000 together. Both carriers start down. Before either address is assigned, real route requests install independent direct routes, reject exclusive duplicates and mismatched deletion filters, and preserve exact dump metadata. Atomic address assignment and withdrawal retain those routes, which can then be deleted. Unconfigured gateways, omitted-interface inference and UDP transmission without a source remain rejected. Actual guest carrier flags gate these checks; QMP restores the links only after they pass. Each boot then retains the existing protocol/scope ownership, dump, legacy alias, unsupported-message, 32-route, 64-socket, packet-count and reserved-byte pressure, vector, copy-fault, epoll, fork/dup, and blocked-writer checks.

Each boot exchanges six routed UDP packets with two independent Ethernet peers. The peers verify checksums, ports, payload, IP destination/source, and ARP next hop for default, on-link, and preserved unowned gateway routes. Firmware traffic is separated by the Ring 3 readiness marker. Evidence is in `build/netlink-*.log` and `build/netlink-results.json`.

The native comparison creates two veth pairs in a private Linux network namespace and leaves both peers down. It waits for actual carrier loss, compares direct-route insertion before an address, atomic address assignment, duplicate rejection, filtered dumps and explicit deletion, then runs the earlier common message, lifetime, route ownership, and adapter checks. Linux flushes device routes when its last address is removed, so its comparison deletes the independent routes before withdrawing those addresses. Axiom64's explicit-route retention across address withdrawal is checked separately in the guest. Host interfaces/routes stay outside the namespace; `build/netlink-native-results.json` records the tested Linux kernel. Axiom64-specific quotas and rejection policies are tested separately in the guest. CI runs both comparisons alongside the earlier networking, full userspace/thread, storage, desktop, ext2-root, formatting, and corresponding-source gates.

Interface references are the pinned [Linux netlink headers](https://github.com/torvalds/linux/blob/v6.12/include/uapi/linux/netlink.h), [route headers](https://github.com/torvalds/linux/blob/v6.12/include/uapi/linux/rtnetlink.h), [IPv4 route control](https://github.com/torvalds/linux/blob/v6.12/net/ipv4/fib_frontend.c), [direct nexthop validation](https://github.com/torvalds/linux/blob/v6.12/net/ipv4/fib_semantics.c), and [netlink socket implementation](https://github.com/torvalds/linux/blob/v6.12/net/netlink/af_netlink.c). These define the broader Linux interface; the implementation supports the subset described above.
