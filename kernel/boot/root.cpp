// SPDX-License-Identifier: GPL-3.0-or-later
#include "boot/root.hpp"
#include "fs/vfs.hpp"

namespace ax {
namespace {
static int option(const char* command, const char* key, char* result, size_t capacity) {
    size_t key_length = strlen(key);
    bool found = false;
    for (size_t at = 0; command[at];) {
        while (command[at] == ' ' || command[at] == '\t')
            at++;
        size_t begin = at;
        while (command[at] && command[at] != ' ' && command[at] != '\t')
            at++;
        size_t length = at - begin;
        if (length < key_length || memcmp(command + begin, key, key_length))
            continue;
        if (found || length == key_length || length - key_length >= capacity)
            return -22;
        found = true;
        memcpy(result, command + begin + key_length, length - key_length);
        result[length - key_length] = 0;
    }
    return found ? 1 : 0;
}

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
    int error = mount_filesystem(destination, source, "ramfs", 0);
    if (error)
        failure(name, error);
}
} // namespace

void boot_root_init(const char* command) {
    char root[32]{}, type[16]{}, flags[16]{};
    int selected = option(command, "root=", root, sizeof(root));
    int filesystem = option(command, "rootfstype=", type, sizeof(type));
    int policy = option(command, "rootflags=", flags, sizeof(flags));
    if (selected < 0 || filesystem < 0 || policy < 0)
        failure("configuration", -22);
    if (!selected || !strcmp(root, "ramfs")) {
        if (filesystem || policy)
            failure("configuration", -22);
        return;
    }
    if (strlen(root) != 8 || memcmp(root, "/dev/vd", 7) || root[7] < 'a' || root[7] > 'h')
        failure("root-device", -19);
    if (filesystem && strcmp(type, "ext2"))
        failure("rootfstype", -19);
    if (policy && strcmp(flags, "ro") && strcmp(flags, "rw"))
        failure("rootflags", -22);
    bool readonly = policy && !strcmp(flags, "ro");
    int error = vfs_disk_root(unsigned(root[7] - 'a'), readonly);
    if (error)
        failure(root, error);
    required("/sbin/init", regular_file, true);
    required("/bin/busybox", regular_file, true);
    required("/lib/ld-musl-x86_64.so.1", regular_file, true);
    const char* volatile_paths[] = {"/dev", "/proc", "/sys", "/tmp", "/run"};
    for (auto name : volatile_paths)
        volatile_mount(name);
    // /tmp is private scratch space even when ordinary root files are persistent.
    auto temporary = lookup("/tmp");
    temporary->mode = directory | 01777;
    log("VFS_ROOT_PASS filesystem=ext2 device=%s readonly=%u\n", root, uint64_t(readonly));
}
} // namespace ax
