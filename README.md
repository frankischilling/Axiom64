# Axiom64

Axiom64 is a standalone x86-64 operating system written in C++ and assembly. Its kernel implements the Linux userspace ABI used by musl programs and runs them in separate user processes.

The QEMU image boots through BIOS and UEFI. It includes persistent ext2 storage, authenticated accounts, BusyBox ash, Bash, zsh, a native GNU C/C++ toolchain, and an Xorg framebuffer desktop with twm and xterm. Full self-hosting and physical-machine support are in development.

- [Build and run](docs/build.md)
- [Architecture, subsystem guides, and current limits](docs/architecture.md)
- [Native development, ports, and licenses](docs/ports.md)
- [Guest tests and CI evidence](docs/testing.md)
- [Milestones](docs/milestones.md) and [feature roadmap](docs/feature-roadmap.md)

The kernel is licensed under [GPL-3.0-or-later](LICENSE). Included userspace packages retain their upstream licenses.
