# SPDX-License-Identifier: GPL-3.0-or-later
# @file    mk/rootfs.mk
# @brief   Build the guest root filesystems and optical image.
# @author  frankischilling
# @date    2026-11-21
#
# Collects guest files and the inputs needed to keep both profiles current.
#
# Copyright (C) 2026 frankischilling
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://gnu.org/licenses/>.

USERSPACE_DATA = $(foreach pattern,*.sh *.conf *.twmrc *.desktop,$(call rwildcard,userspace/,$(pattern))) \
	$(wildcard userspace/tests/toolchain/*)
ROOTFS_INPUTS = build/thread-io-static build/thread-io-dynamic build/lifecycle-static \
	build/lifecycle-dynamic build/futex-static build/futex-dynamic build/thread-static \
	build/thread-dynamic build/abi-static build/abi-dynamic build/init build/ipc-tests \
	build/signal-tests build/storage-tests build/vfs-tests build/ext2-tests build/root-tests \
	build/net-tests build/ipv4-tests build/udp-tests build/x11-probe build/licenses/.stamp \
	$(USERSPACE_DATA) ports.lock.json dependencies.json scripts/rootfs.py scripts/ports.py \
	scripts/build_busybox.py scripts/fetch.py
ROOTFS_INPUTS += build/network-manager scripts/configure-busybox.sh build/random-seed-static
ROOTFS_INPUTS += scripts/build_libcap.py scripts/build_musl.py scripts/build_openssl.py sources.lock.json
ROOTFS_INPUTS += scripts/build_libxcrypt.py scripts/linux_uapi.py scripts/build_curl.py scripts/ca_bundle.py
ROOTFS_INPUTS += scripts/build_accounts.py $(wildcard userspace/accounts/*.c userspace/accounts/*.h)
ROOTFS_INPUTS += $(wildcard userspace/desktop/*.c userspace/desktop/*.h) build/desktop-terminal build/desktop-session-bus
ROOTFS_INPUTS += $(DOOM_INPUTS) mk/rootfs.mk

build/desktop-session-bus: userspace/desktop/session-bus.c
	@mkdir -p build
	$(MUSL_CC) -std=c11 -O2 -g -Wall -Wextra -Werror -static $< -o $@

build/rootfs.cpio: $(ROOTFS_INPUTS) | busybox
	$(PYTHON) scripts/rootfs.py

build/rootfs-desktop.cpio: $(ROOTFS_INPUTS) | busybox
	$(PYTHON) scripts/rootfs.py --profile desktop

image: build/axiom64.elf build/rootfs.cpio
	$(PYTHON) scripts/image.py

.PHONY: test-weston
test-weston: build/axiom64.elf build/rootfs-desktop.cpio
	$(PYTHON) scripts/weston_test.py $(WESTON_TEST_FLAGS)
