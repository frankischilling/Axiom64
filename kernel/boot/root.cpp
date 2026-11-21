// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/boot/root.cpp
 * @brief   Root filesystem bootstrap.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Uses boot arguments and available block devices to select and mount the
 * initial root filesystem.
 *
 * Copyright (C) 2026 frankischilling
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://gnu.org/licenses/>.
 */
#include "boot/root.hpp"
#include "boot/arguments.hpp"
#include "drivers/block/partition.hpp"
#include "fs/ext2/ext2.hpp"
#include "fs/vfs.hpp"

namespace ax {
namespace {
[[noreturn]] static void failure(const char* stage, int error) {
    log("BOOT_ROOT_FAIL stage=%s errno=%d\n", stage, int64_t(-error));
    poweroff(1);
}

static Path path(const char* text) {
    Path value;
    value.base = root_node;
    memcpy(value.text, text, strlen(text) + 1);
    value.error = 0;
    return value;
}

static void required(const char* name, uint32_t kind, bool executable = false) {
    Node* node = nullptr;
    int error = resolve_path(path(name), node);
    if (error)
        failure(name, error);
    if ((node->mode & 0170000) != kind || (executable && !(node->mode & 0111)))
        failure(name, -13);
}

static void volatile_mount(const char* name) {
    required(name, directory);
    Path destination = path(name), source = path("");
    int error = mount_filesystem(destination, source, !strcmp(name, "/proc") ? "proc" : "ramfs", 0);
    if (error)
        failure(name, error);
}

static void ipc_mount(const char* name, const char* type) {
    Path destination = path(name);
    Node* point = nullptr;
    int error = resolve_path(destination, point, false);
    if (error == -2)
        error = create_node(destination, directory | 0755, point);
    if (error)
        failure(name, error);
    if ((point->mode & 0170000) != directory)
        failure(name, -20);
    constexpr unsigned nosuid = 2, nodev = 4;
    error = mount_filesystem(destination, path(""), type, nosuid | nodev);
    if (error)
        failure(name, error);
    lookup(name)->mode = directory | 01777;
}

static void descriptor_links() {
    const char* names[] = {"/dev/fd", "/dev/stdin", "/dev/stdout", "/dev/stderr"};
    const char* targets[] = {"/proc/self/fd", "/proc/self/fd/0", "/proc/self/fd/1",
                             "/proc/self/fd/2"};
    for (unsigned i = 0; i < sizeof(names) / sizeof(*names); i++) {
        auto name = path(names[i]);
        Node* node = nullptr;
        int error = resolve_path(name, node, false);
        if (error == -2)
            error = create_node(name, symlink | 0777, node, targets[i]);
        if (error)
            failure(names[i], error);
    }
}
} // namespace

void boot_root_init(const BootArguments& arguments, const char* init) {
    char root[sizeof("PARTLABEL=") - 1 + partition_label_size]{}, type[16]{}, flags[32]{};
    int selected = arguments.read("root=", root, sizeof(root));
    int filesystem = arguments.read("rootfstype=", type, sizeof(type));
    int policy = arguments.read("rootflags=", flags, sizeof(flags));
    if (selected < 0 || filesystem < 0 || policy < 0)
        failure("configuration", -22);
    if (strlen(root) >= 32 && memcmp(root, "PARTUUID=", 9) && memcmp(root, "PARTLABEL=", 10))
        failure("configuration", -22);
    if (!selected || !strcmp(root, "ramfs")) {
        if (filesystem || policy)
            failure("configuration", -22);
        required(init, regular_file, true);
        volatile_mount("/proc");
        ipc_mount("/dev/shm", "ramfs");
        ipc_mount("/dev/mqueue", "mqueue");
        descriptor_links();
        return;
    }
    int device = block_find(root);
    if (device < 0)
        failure("root-device", device);
    if (filesystem && !ext_volume_type(type))
        failure("rootfstype", -19);
    bool checked =
        policy && (!strcmp(flags, "ro,recovery=check") || !strcmp(flags, "rw,recovery=check"));
    if (policy && strcmp(flags, "ro") && strcmp(flags, "rw") && !checked)
        failure("rootflags", -22);
    bool readonly = policy && (!strcmp(flags, "ro") || !strcmp(flags, "ro,recovery=check"));
    int error = vfs_disk_root(unsigned(device), readonly, checked);
    if (error)
        failure(root, error);
    required(init, regular_file, true);
    required("/bin/busybox", regular_file, true);
    required("/lib/ld-musl-x86_64.so.1", regular_file, true);
    const char* volatile_paths[] = {"/dev", "/proc", "/sys", "/tmp", "/run"};
    for (auto name : volatile_paths)
        volatile_mount(name);
    ipc_mount("/dev/shm", "ramfs");
    ipc_mount("/dev/mqueue", "mqueue");
    descriptor_links();
    // /tmp is private scratch space even when ordinary root files are persistent.
    auto temporary = lookup("/tmp");
    temporary->mode = directory | 01777;
    log("VFS_ROOT_PASS filesystem=%s device=%s readonly=%u\n", filesystem ? type : "ext2", root,
        uint64_t(readonly));
}
} // namespace ax
