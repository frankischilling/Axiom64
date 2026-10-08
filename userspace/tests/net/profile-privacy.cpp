// SPDX-License-Identifier: GPL-3.0-or-later
#include "net/config/profile.hpp"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#ifndef PROFILE_LINKAGE
#define PROFILE_LINKAGE "static"
#endif

using namespace ax::net;
static const ax::dhcp::Identity identity{{0x52, 0x54, 0, 0x12, 0x34, 0x10}, "axiom64"};
static const char* const suffixes[]{"conf", "lease"};

enum class Fault { none, write, read, close, sync, mode, directory_mode, rename };
static Fault fault;
static unsigned fault_count;

static bool fail(Fault operation) {
    if (fault != operation || --fault_count)
        return false;
    fault = Fault::none;
    errno = EIO;
    return true;
}

extern "C" {
ssize_t __real_write(int, const void*, size_t);
ssize_t __real_read(int, void*, size_t);
int __real_close(int);
int __real_fsync(int);
int __real_fchmod(int, mode_t);
int __real_fchmodat(int, const char*, mode_t, int);
int __real_renameat(int, const char*, int, const char*);

ssize_t __wrap_write(int fd, const void* bytes, size_t size) {
    return fail(Fault::write) ? -1 : __real_write(fd, bytes, size);
}

ssize_t __wrap_read(int fd, void* bytes, size_t size) {
    return fail(Fault::read) ? -1 : __real_read(fd, bytes, size);
}

int __wrap_close(int fd) {
    struct stat value;
    bool temporary = fault == Fault::close && fstat(fd, &value) == 0 && S_ISREG(value.st_mode) &&
                     (fcntl(fd, F_GETFL) & O_ACCMODE) == O_WRONLY;
    int result = __real_close(fd);
    return temporary && fail(Fault::close) ? -1 : result;
}

int __wrap_fsync(int fd) {
    return fail(Fault::sync) ? -1 : __real_fsync(fd);
}

int __wrap_fchmod(int fd, mode_t mode) {
    return fail(Fault::mode) ? -1 : __real_fchmod(fd, mode);
}

int __wrap_fchmodat(int fd, const char* name, mode_t mode, int flags) {
    return fail(Fault::directory_mode) ? -1 : __real_fchmodat(fd, name, mode, flags);
}

int __wrap_renameat(int old_fd, const char* old_name, int new_fd, const char* new_name) {
    return fail(Fault::rename) ? -1 : __real_renameat(old_fd, old_name, new_fd, new_name);
}
}

static void check(bool good, const char* message) {
    if (!good) {
        fprintf(stderr, "PROFILE_PRIVACY_FAIL %s errno=%d uid=%ld linkage=%s\n", message, errno,
                long(geteuid()), PROFILE_LINKAGE);
        exit(1);
    }
}

static void join(char* output, size_t capacity, const char* root, const char* leaf) {
    int size = snprintf(output, capacity, "%s/%s", root, leaf);
    check(size > 0 && size_t(size) < capacity, "bounded fixture path");
}

static void rejected(const Store& store, const char* interface, int expected) {
    Profile output;
    output.address = 0xabcdef01;
    output.metric = 1234;
    unsigned char before[sizeof(output)];
    memcpy(before, &output, sizeof(output));
    int error = store.read_profile(interface, output);
    check(error && (!expected || error == expected) && !memcmp(before, &output, sizeof(output)),
          "rejected profile preserves the entire caller snapshot");
    uint32_t hint = 0xabcdef01;
    error = store.read_hint(interface, identity, hint);
    check(error && (!expected || error == expected) && hint == 0xabcdef01,
          "rejected hint preserves caller output");
}

static void valid(const Store& store) {
    Profile output;
    uint32_t hint = 0;
    check(store.read_profile("eth0", output) == 0 && output.metric == 1400 &&
              store.read_hint("eth0", identity, hint) == 0 && hint == 0x0a170128,
          "private profile and hint remain usable");
}

static void metadata(const char* path, unsigned mode, bool directory = false) {
    struct stat value;
    check(lstat(path, &value) == 0 && (value.st_mode & 07777) == mode &&
              value.st_uid == geteuid() &&
              (directory ? S_ISDIR(value.st_mode) : S_ISREG(value.st_mode) && value.st_nlink == 1),
          "created objects have exact private modes and owner");
}

static void privacy(const char* root) {
    char directory[256], profile[300], hint[300], other[320];
    join(directory, sizeof(directory), root, "private");
    join(profile, sizeof(profile), directory, "eth0.conf");
    join(hint, sizeof(hint), directory, "eth0.lease");
    Store store(directory);
    Profile original;
    original.metric = 1400;
    check(store.write_profile("eth0", original) == 0 &&
              store.write_hint("eth0", identity, 0x0a170128) == 0,
          "create private saved fixtures");
    metadata(directory, 0700, true);
    metadata(profile, 0600);
    metadata(hint, 0600);
    valid(store);
    const char invalid_profile[] = "axiom64-network=2\nmode=dhcp\n";
    const char invalid_hint[] = "axiom64-lease=2\n";
    int damaged = open(profile, O_WRONLY | O_TRUNC | O_CLOEXEC);
    check(damaged >= 0 &&
              write(damaged, invalid_profile, sizeof(invalid_profile) - 1) ==
                  ssize_t(sizeof(invalid_profile) - 1) &&
              close(damaged) == 0,
          "malformed profile on a valid private inode");
    damaged = open(hint, O_WRONLY | O_TRUNC | O_CLOEXEC);
    check(damaged >= 0 &&
              write(damaged, invalid_hint, sizeof(invalid_hint) - 1) ==
                  ssize_t(sizeof(invalid_hint) - 1) &&
              close(damaged) == 0,
          "malformed hint on a valid private inode");
    rejected(store, "eth0", EINVAL);
    char oversized[4096];
    memset(oversized, 'x', sizeof(oversized));
    const char* const saved_paths[]{profile, hint};
    for (const char* saved_path : saved_paths) {
        damaged = open(saved_path, O_WRONLY | O_TRUNC | O_CLOEXEC);
        check(damaged >= 0 &&
                  write(damaged, oversized, sizeof(oversized)) == ssize_t(sizeof(oversized)) &&
                  close(damaged) == 0,
              "oversized saved input fixture");
    }
    rejected(store, "eth0", EFBIG);
    check(store.write_profile("eth0", original) == 0 &&
              store.write_hint("eth0", identity, 0x0a170128) == 0,
          "atomic replacement repairs malformed private contents");
    valid(store);
    const unsigned file_modes[]{0644, 0620, 0400, 0000, 01600, 02600, 04600, 0666};
    for (unsigned mode : file_modes) {
        check(chmod(profile, mode) == 0 && chmod(hint, mode) == 0, "saved mode fixture");
        rejected(store, "eth0", EACCES);
        check(store.write_profile("eth0", original) == EACCES &&
                  store.write_hint("eth0", identity, 0x0a170128) == EACCES &&
                  store.forget_hint("eth0") == EACCES,
              "unsafe saved files survive rejected replacement and removal");
        check(chmod(profile, 0600) == 0 && chmod(hint, 0600) == 0, "restore saved modes");
    }
    const unsigned directory_modes[]{0755, 0777, 0500, 0000, 01700, 02700, 04700};
    for (unsigned mode : directory_modes) {
        check(chmod(directory, mode) == 0, "directory mode fixture");
        rejected(store, "eth0", EACCES);
        check(store.write_profile("eth0", original) == EACCES &&
                  store.write_hint("eth0", identity, 0x0a170128) == EACCES &&
                  store.forget_hint("eth0") == EACCES,
              "unsafe private directory is never adopted or modified");
        check(chmod(directory, 0700) == 0, "restore directory mode");
    }
    join(other, sizeof(other), directory, "profile-link");
    check(link(profile, other) == 0, "real saved-profile hard link");
    char hint_link[320];
    join(hint_link, sizeof(hint_link), directory, "hint-link");
    check(link(hint, hint_link) == 0, "real saved-hint hard link");
    rejected(store, "eth0", EACCES);
    check(store.forget_hint("eth0") == EACCES && unlink(other) == 0 && unlink(hint_link) == 0,
          "multiply linked hint is preserved");
    valid(store);
    join(other, sizeof(other), root, "alias");
    check(symlink("private", other) == 0, "directory symlink fixture");
    Store alias(other);
    rejected(alias, "eth0", 0);
    check(alias.write_profile("eth0", original) != 0 && alias.forget_hint("eth0") != 0 &&
              unlink(other) == 0,
          "directory symlink cannot redirect saved operations");
    const char* const spellings[]{"private/../private", "private/./", "private//child"};
    for (const char* spelling : spellings) {
        join(other, sizeof(other), root, spelling);
        Store invalid(other);
        rejected(invalid, "eth0", EINVAL);
        check(invalid.write_profile("eth0", original) == EINVAL &&
                  invalid.forget_hint("eth0") == EINVAL,
              "unsafe components rejected before missing-file interpretation");
    }
    for (const char* suffix : suffixes) {
        snprintf(other, sizeof(other), "%s/eth1.%s", directory, suffix);
        char target[32];
        snprintf(target, sizeof(target), "eth0.%s", suffix);
        check(symlink(target, other) == 0, "saved file symlink fixture");
    }
    rejected(store, "eth1", ELOOP);
    check(store.forget_hint("eth1") == ELOOP, "hint symlink is not removed");
    for (const char* suffix : suffixes) {
        snprintf(other, sizeof(other), "%s/eth1.%s", directory, suffix);
        check(unlink(other) == 0 && mkdir(other, 0700) == 0, "nonregular saved fixture");
    }
    rejected(store, "eth1", EINVAL);
    check(store.forget_hint("eth1") == EINVAL, "nonregular hint is preserved");
    for (const char* suffix : suffixes) {
        snprintf(other, sizeof(other), "%s/eth1.%s", directory, suffix);
        check(rmdir(other) == 0, "remove nonregular test fixtures");
    }
    join(other, sizeof(other), root, "missing");
    Store missing(other);
    rejected(missing, "eth0", ENOENT);
    check(missing.forget_hint("eth0") == 0 && store.forget_hint("eth2") == 0,
          "validated missing hints can be forgotten repeatedly");
    int baseline = open("/dev/null", O_RDONLY | O_CLOEXEC);
    check(baseline >= 0 && close(baseline) == 0, "descriptor leak baseline");
    check(chmod(directory, 0755) == 0, "repeated rejected directory fixture");
    for (unsigned i = 0; i < 300; i++)
        rejected(store, "eth0", EACCES);
    int after = open("/dev/null", O_RDONLY | O_CLOEXEC);
    check(after == baseline && close(after) == 0 && chmod(directory, 0700) == 0,
          "repeated failed traversals release every descriptor");
    valid(store);
    check(store.forget_hint("eth0") == 0 && unlink(profile) == 0 && rmdir(directory) == 0,
          "only owned saved fixtures removed");
    puts("PROFILE_PRIVACY_FILES_PASS");
}

static void ancestors_and_umask(const char* root) {
    char parent[256], child[256], profile[300], hint[300];
    join(parent, sizeof(parent), root, "ancestor");
    join(child, sizeof(child), parent, "private");
    Store store(child);
    Profile original;
    original.metric = 1400;
    mode_t previous = umask(0777);
    int first = store.write_profile("eth0", original);
    int second = store.write_hint("eth0", identity, 0x0a170128);
    umask(previous);
    check(!first && !second, "restrictive umask cannot make new private objects unusable");
    join(profile, sizeof(profile), child, "eth0.conf");
    join(hint, sizeof(hint), child, "eth0.lease");
    metadata(parent, 0700, true);
    metadata(child, 0700, true);
    metadata(profile, 0600);
    metadata(hint, 0600);
    valid(store);
    check(chmod(parent, 0777) == 0, "writable non-sticky ancestor fixture");
    rejected(store, "eth0", EACCES);
    check(store.write_profile("eth0", original) == EACCES && store.forget_hint("eth0") == EACCES,
          "untrusted ancestor prevents writes and deletion");
    check(chmod(parent, 01777) == 0, "trusted sticky ancestor fixture");
    valid(store);
    check(store.write_profile("eth0", original) == 0 && store.forget_hint("eth0") == 0,
          "owner's sticky parent permits private saved operations");
    check(unlink(profile) == 0 && rmdir(child) == 0 && rmdir(parent) == 0,
          "nested private directories cleaned");
    puts("PROFILE_PRIVACY_ANCESTORS_UMASK_PASS");
}

static void failures(const char* root) {
    char directory[256], name[300];
    join(directory, sizeof(directory), root, "atomic");
    join(name, sizeof(name), directory, "eth0.conf");
    Store store(directory);
    Profile original;
    original.metric = 1400;
    Profile replacement;
    replacement.method = Method::disabled;
    replacement.metric = 1700;
    check(store.write_profile("eth0", original) == 0, "atomic failure fixture");
    const Fault operations[]{Fault::write, Fault::close, Fault::sync, Fault::mode, Fault::rename};
    for (Fault operation : operations) {
        fault = operation;
        fault_count = 1;
        check(store.write_profile("eth0", replacement) == EIO && fault == Fault::none,
              "precommit write, close, sync, mode, and rename failures are reported");
        Profile output;
        check(store.read_profile("eth0", output) == 0 && output.method == Method::dhcp &&
                  output.metric == 1400,
              "failed publication preserves the complete old snapshot");
    }
    fault = Fault::sync;
    fault_count = 2;
    check(store.write_profile("eth0", replacement) == EIO && fault == Fault::none,
          "postcommit directory synchronization failure is reported");
    Profile output;
    check(store.read_profile("eth0", output) == 0 && output.method == Method::disabled &&
              output.metric == 1700,
          "postcommit failure retains a complete new snapshot");
    unsigned char snapshot[sizeof(output)];
    memcpy(snapshot, &output, sizeof(output));
    fault = Fault::read;
    fault_count = 1;
    check(store.read_profile("eth0", output) == EIO && fault == Fault::none &&
              !memcmp(snapshot, &output, sizeof(output)),
          "failed file read preserves complete caller output");
    check(store.write_hint("eth0", identity, 0x0a170128) == 0, "hint read-failure fixture");
    uint32_t hint = 0xabcdef01;
    fault = Fault::read;
    fault_count = 1;
    check(store.read_hint("eth0", identity, hint) == EIO && fault == Fault::none &&
              hint == 0xabcdef01,
          "failed hint read preserves caller output");
    check(store.forget_hint("eth0") == 0 && unlink(name) == 0 && rmdir(directory) == 0,
          "failed publication leaves no temporary file or descriptor behind");
    fault = Fault::directory_mode;
    fault_count = 1;
    check(store.write_profile("eth0", original) == EIO && fault == Fault::none &&
              rmdir(directory) == 0,
          "failed new-directory permission restoration is reported");
    puts("PROFILE_PRIVACY_FAILURES_PASS");
}

static void native(const char* root) {
    char path[256], name[300];
    const char* const fixtures[]{"foreign-directory", "foreign-ancestor/private", "foreign-file"};
    for (const char* fixture : fixtures) {
        join(path, sizeof(path), root, fixture);
        Store store(path);
        rejected(store, "eth0", EACCES);
        Profile original;
        check(store.write_profile("eth0", original) == EACCES &&
                  store.write_hint("eth0", identity, 0x0a170128) == EACCES &&
                  store.forget_hint("eth0") == EACCES,
              "real foreign ownership prevents saved reads, writes, and deletion");
    }
    join(path, sizeof(path), root, "special");
    check(mkdir(path, 0700) == 0, "native special-file fixture directory");
    Store store(path);
    for (const char* suffix : suffixes) {
        snprintf(name, sizeof(name), "%s/eth0.%s", path, suffix);
        check(mkfifo(name, 0600) == 0, "writerless FIFO fixture");
    }
    alarm(2);
    rejected(store, "eth0", EINVAL);
    check(store.forget_hint("eth0") == EINVAL, "writerless FIFO cannot block hint removal");
    alarm(0);
    for (const char* suffix : suffixes) {
        snprintf(name, sizeof(name), "%s/eth0.%s", path, suffix);
        check(unlink(name) == 0, "remove writerless FIFO fixture");
        int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        sockaddr_un endpoint{};
        endpoint.sun_family = AF_UNIX;
        check(strlen(name) < sizeof(endpoint.sun_path), "bounded socket fixture path");
        strcpy(endpoint.sun_path, name);
        check(fd >= 0 && bind(fd, reinterpret_cast<sockaddr*>(&endpoint), sizeof(endpoint)) == 0 &&
                  close(fd) == 0,
              "native socket saved-path fixture");
    }
    rejected(store, "eth0", EINVAL);
    for (const char* suffix : suffixes) {
        snprintf(name, sizeof(name), "%s/eth0.%s", path, suffix);
        check(unlink(name) == 0, "remove native socket fixture");
    }
    check(rmdir(path) == 0, "remove native special-file directory");
    puts("PROFILE_PRIVACY_NATIVE_TYPES_OWNERS_PASS");
}

int main(int argc, char** argv) {
    bool linux = argc == 3 && !strcmp(argv[1], "--native");
    check(argc <= 2 || linux, "profile fixture arguments");
    char temporary[] = "/tmp/axiom64-profile-XXXXXX";
    const char* root = linux ? argv[2] : argc == 2 ? argv[1] : mkdtemp(temporary);
    check(root && (mkdir(root, 0700) == 0 || errno == EEXIST), "private fixture root");
    privacy(root);
    ancestors_and_umask(root);
    failures(root);
    if (linux)
        native(root);
    if (argc == 1)
        check(rmdir(root) == 0, "all temporary fixtures cleaned");
    printf("PROFILE_PRIVACY_TESTS_PASS linkage=%s uid=%ld\n", PROFILE_LINKAGE, long(geteuid()));
    return 0;
}
