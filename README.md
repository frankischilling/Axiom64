# Axiom64

Axiom64 is a standalone x86-64 operating system written in C++ and Assembly. Its kernel implements the Linux userspace ABI used by musl programs, with a modular monolith architecture and separate user processes.

The QEMU image supports BIOS and UEFI boot. It includes BusyBox ash, Bash, zsh, a native GNU C/C++ toolchain, and an Xorg framebuffer desktop with twm and xterm.

- [Build and run](docs/build.md)
- [Architecture and current limits](docs/architecture.md)
- [Guest tests and CI evidence](docs/testing.md)
- [Persistent disks and writable filesystems](docs/storage.md)
- [Filesystems and mounts](docs/vfs.md)
- [Threads and futexes](docs/threads.md)
- [Ethernet and packet sockets](docs/network.md)
- [IPv4, ARP, routing, and ping](docs/ipv4.md)
- [IPv4 UDP sockets](docs/udp.md)
- [IPv4 netlink route and address control](docs/netlink.md)
- [IPv4 configuration and DHCP modules](docs/network-configuration.md)
- [Userspace ports, licenses, and source bundles](docs/ports.md)
- [Development milestones](docs/milestones.md)
- [Full feature and application roadmap](docs/feature-roadmap.md)

The kernel is licensed under [GPL-3.0-or-later](LICENSE). Included userspace packages retain their upstream licenses.
