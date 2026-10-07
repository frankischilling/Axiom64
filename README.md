# Axiom64

Axiom64 is a standalone x86-64 operating system with a C++ kernel and assembly for CPU entry. Its kernel implements the Linux syscall ABI used by musl programs.

The current image boots in QEMU through BIOS or UEFI. It runs static and dynamically linked musl executables and an upstream BusyBox ash shell in Ring 3. The boot tests exercise private address spaces, fork, exec, wait, files, pipes, directory traversal, and shell pipelines. A native GNU toolchain and an Xorg framebuffer environment are the next milestones.

Build on Ubuntu 24.04 or a matching WSL environment:

```sh
sudo apt-get install g++ make musl-tools linux-libc-dev nasm python3 xorriso qemu-system-x86 ovmf
make -j2 image
make test
make run
```

`make run` opens the serial shell in the terminal. The ISO is `build/axiom64.iso`; it includes both BIOS and UEFI boot paths. `make test` builds a separate test ISO and requires userspace success markers and a clean guest exit under both firmware types. Logs and machine-readable results are written under `build/`.

Downloads are pinned by SHA-256 in `dependencies.json`. BusyBox is built against musl without kernel-specific patches. The image uses Limine as its bootloader. Third-party licenses are included in the image; the kernel uses the license in [LICENSE](LICENSE).

See [ARCHITECTURE.md](ARCHITECTURE.md) for the implementation and current limits, and [docs/milestones.md](docs/milestones.md) for the full development scope.
