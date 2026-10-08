// SPDX-License-Identifier: GPL-3.0-or-later
#include "net/config/resolver.hpp"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

using namespace ax;
constexpr char prefix[] = "# Axiom64 generated resolver configuration\n";
static char base[100];
static unsigned rename_failures = 0, rename_calls = 0;
static unsigned sync_failure = 0, sync_calls = 0;
static bool directory_mode_failure = false, file_mode_failure = false;

// Fault only the linked fixture's filesystem calls. The production modules
// still use the real file operations before and after the selected failure.
extern "C" int __real_rename(const char*, const char*);
extern "C" int __real_fsync(int);
extern "C" int __real_chmod(const char*, mode_t);
extern "C" int __real_fchmod(int, mode_t);

extern "C" int __wrap_rename(const char* from, const char* to) {
    if (rename_failures && ++rename_calls <= 32 && (rename_failures & (1u << (rename_calls - 1)))) {
        errno = EIO;
        return -1;
    }
    return __real_rename(from, to);
}

extern "C" int __wrap_fsync(int fd) {
    if (sync_failure && ++sync_calls == sync_failure) {
        errno = EIO;
        return -1;
    }
    return __real_fsync(fd);
}

extern "C" int __wrap_chmod(const char* name, mode_t mode) {
    if (directory_mode_failure) {
        directory_mode_failure = false;
        errno = EACCES;
        return -1;
    }
    return __real_chmod(name, mode);
}

extern "C" int __wrap_fchmod(int fd, mode_t mode) {
    if (file_mode_failure) {
        file_mode_failure = false;
        errno = EACCES;
        return -1;
    }
    return __real_fchmod(fd, mode);
}

static void check(bool value, const char* reason) {
    if (!value) {
        fprintf(stderr, "RESOLVER_FAIL %s errno=%d\n", reason, errno);
        exit(1);
    }
}

static void path(char* result, const char* suffix) {
    snprintf(result, 300, "%s/%s", base, suffix);
}

static size_t read_file(const char* name, void* output, size_t capacity) {
    int fd = open(name, O_RDONLY | O_CLOEXEC);
    ssize_t count = fd < 0 ? -1 : read(fd, output, capacity);
    check(count >= 0 && size_t(count) < capacity && close(fd) == 0, "read actual fixture file");
    return size_t(count);
}

static void write_file(const char* name, const void* input, size_t size) {
    int fd = open(name, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    check(fd >= 0 && write(fd, input, size) == ssize_t(size) && fsync(fd) == 0 && close(fd) == 0,
          "write controlled fixture file");
}

static void content(const char* name, const char* expected) {
    char text[2048];
    size_t size = read_file(name, text, sizeof(text));
    check(size == strlen(expected) && !memcmp(text, expected, size), "exact resolver contents");
    size_t line = 0;
    for (size_t i = 0; i < size; i++) {
        check(++line <= 255, "complete lines fit the pinned musl parser");
        if (text[i] == '\n')
            line = 0;
    }
}

static dhcp::Parameters metadata(uint32_t a, uint32_t b = 0, uint32_t c = 0) {
    dhcp::Parameters value;
    const uint32_t servers[]{a, b, c};
    for (uint32_t server : servers)
        if (server)
            value.dns[value.dns_count++] = server;
    return value;
}

static void merge() {
    char runtime[300], target[300], generated[300];
    path(runtime, "merge");
    path(target, "merge-link");
    path(generated, "merge/resolv.conf");
    net::Store store(runtime);
    net::Resolver resolver;
    check(resolver.open(store, target) == 0 && resolver.managed() && !resolver.limited(),
          "create an owned file and previously absent resolver link");
    content(target, prefix);
    char link[300];
    ssize_t length = readlink(target, link, sizeof(link));
    check(length == ssize_t(strlen(generated)) && !memcmp(link, generated, size_t(length)),
          "link points exactly to the selected runtime file");
    struct stat information;
    check(stat(runtime, &information) == 0 && (information.st_mode & 0777) == 0755 &&
              stat(generated, &information) == 0 && (information.st_mode & 0777) == 0644,
          "runtime directory and generated resolver text are readable by applications");
    char record[300];
    path(record, "merge/resolv.owned");
    check(stat(record, &information) == 0 && (information.st_mode & 0777) == 0600,
          "ownership record has private permissions");
    auto primary = metadata(0xc0000201, 0xc0000202);
    strcpy(primary.domain, "lab.example");
    auto secondary = metadata(0xc0000202, 0xc0000203);
    strcpy(secondary.search, "LAB.Example. dev.lab.example");
    check(resolver.update(2, secondary, 20) == 0 && resolver.update(1, primary, 10) == 0 &&
              !resolver.limited(),
          "merge by metric with canonical nameserver and search deduplication");
    char expected[1024];
    snprintf(expected, sizeof(expected),
             "%snameserver 192.0.2.1\nnameserver 192.0.2.2\n"
             "nameserver 192.0.2.3\nsearch lab.example dev.lab.example\n",
             prefix);
    content(target, expected);
    int old = open(target, O_RDONLY | O_CLOEXEC);
    check(old >= 0, "retain old generated inode across publication");
    primary = metadata(0xc0000204);
    strcpy(primary.search, "STATIC.EXAMPLE.");
    check(resolver.update(1, primary, 2) == 0, "replace one interface's metadata");
    char held[1024];
    ssize_t size = read(old, held, sizeof(held));
    check(size == ssize_t(strlen(expected)) && !memcmp(held, expected, size) && close(old) == 0,
          "atomic replacement preserves an already open description");
    snprintf(expected, sizeof(expected),
             "%snameserver 192.0.2.4\nnameserver 192.0.2.2\n"
             "nameserver 192.0.2.3\nsearch static.example lab.example dev.lab.example\n",
             prefix);
    content(target, expected);
    secondary = metadata(0xc0000203, 0xc0000205, 0xc0000206);
    check(resolver.update(2, secondary, 10) == 0 && resolver.limited(),
          "report distinct nameservers beyond libc's three-server bound");
    check(resolver.withdraw(2) == 0 && !resolver.limited(), "withdraw only one contribution");
    snprintf(expected, sizeof(expected), "%snameserver 192.0.2.4\nsearch static.example\n", prefix);
    content(target, expected);
    check(resolver.update(0, primary) == EINVAL && resolver.update(9, primary) == EINVAL &&
              resolver.update(1, primary, 1) == EINVAL && resolver.withdraw(9) == EINVAL,
          "reject invalid indices and priority before mutation");
    auto invalid = primary;
    invalid.dns_count = 4;
    check(resolver.update(1, invalid) == EINVAL, "reject an oversized nameserver input");
    invalid = primary;
    memset(invalid.search, 'a', sizeof(invalid.search));
    check(resolver.update(1, invalid) == EINVAL,
          "reject unterminated names without reading past input");
    content(target, expected);
    check(resolver.withdraw(1) == 0, "withdraw the final owned contribution");
    content(target, prefix);
    puts("RESOLVER_MERGE_PASS");
}

static void limits() {
    char runtime[300], target[300];
    path(runtime, "limits");
    path(target, "limits-link");
    net::Store store(runtime);
    net::Resolver resolver;
    check(resolver.open(store, target) == 0, "open bounded metadata fixture");
    for (unsigned i = 1; i <= 8; i++) {
        auto value = metadata(0xc0000200 + i);
        snprintf(value.domain, sizeof(value.domain), "interface%u.example", i);
        check(resolver.update(i, value) == 0, "all eight contribution slots work");
    }
    check(resolver.limited(), "report nameserver and search-list limits");
    char expected[1024];
    snprintf(expected, sizeof(expected),
             "%snameserver 192.0.2.1\nnameserver 192.0.2.2\n"
             "nameserver 192.0.2.3\nsearch interface1.example interface2.example "
             "interface3.example interface4.example interface5.example interface6.example\n",
             prefix);
    content(target, expected);
    for (unsigned i = 1; i <= 8; i++)
        check(resolver.withdraw(i) == 0, "release each bounded contribution");
    auto value = metadata(0xc0000201);
    unsigned at = 0;
    for (unsigned label = 0; label < 4; label++) {
        unsigned count = label == 3 ? 55 : 63;
        memset(value.search + at, 'a' + label, count);
        at += count;
        if (label != 3)
            value.search[at++] = '.';
    }
    check(at == 247 && resolver.update(1, value) == 0 && !resolver.limited(),
          "exact longest complete search line is accepted");
    snprintf(expected, sizeof(expected), "%snameserver 192.0.2.1\nsearch %s\n", prefix,
             value.search);
    content(target, expected);
    memset(value.search + at, 'd', 6);
    strcpy(value.search + at + 6, " ok.example");
    check(resolver.update(1, value) == 0 && resolver.limited(),
          "skip an oversized complete domain while reporting the limit");
    snprintf(expected, sizeof(expected), "%snameserver 192.0.2.1\nsearch ok.example\n", prefix);
    content(target, expected);
    puts("RESOLVER_LIMITS_PASS interfaces=8 search_line=255");
}

static void manual() {
    char runtime[300], target[300], destination[300], generated[300];
    path(runtime, "manual");
    path(target, "manual-target");
    path(destination, "manual-other");
    constexpr char text[] = "# kept by its administrator\nnameserver 198.51.100.53\n";
    write_file(target, text, sizeof(text) - 1);
    net::Store store(runtime);
    net::Resolver regular;
    auto value = metadata(0xc0000201);
    check(regular.open(store, target) == 0 && !regular.managed() && regular.update(1, value) == 0,
          "manual regular file takes precedence");
    content(target, text);
    check(unlink(target) == 0, "release manual regular fixture");
    write_file(destination, text, sizeof(text) - 1);
    check(symlink(destination, target) == 0, "prepare foreign resolver symlink");
    net::Resolver foreign;
    check(foreign.open(store, target) == 0 && !foreign.managed() && foreign.update(1, value) == 0,
          "foreign symlink and its destination stay manual");
    content(destination, text);
    check(unlink(target) == 0, "release foreign-link fixture");
    net::Resolver owned;
    check(owned.open(store, target) == 0 && owned.update(1, value) == 0,
          "prepare an owned file before manual editing");
    path(generated, "manual/resolv.conf");
    write_file(generated, text, sizeof(text) - 1);
    check(owned.update(1, metadata(0xc0000202)) == 0 && !owned.managed() && owned.withdraw(1) == 0,
          "editing through the owned link preserves manual contents");
    content(target, text);
    owned.close();
    net::Resolver restarted;
    check(restarted.open(store, target) == 0 && !restarted.managed(),
          "restart cannot adopt manually changed generated contents");
    content(target, text);
    puts("RESOLVER_MANUAL_PRESERVATION_PASS");
}

static void manual_takeover() {
    char runtime[300], target[300], generated[300];
    path(runtime, "takeover");
    path(target, "takeover-link");
    path(generated, "takeover/resolv.conf");
    net::Store store(runtime);
    net::Resolver resolver;
    check(resolver.open(store, target) == 0 && resolver.update(1, metadata(0xc0000201)) == 0,
          "prepare a live owned resolver before target replacement");
    char expected[1024];
    snprintf(expected, sizeof(expected), "%snameserver 192.0.2.1\n", prefix);
    constexpr char text[] = "# replaced by its administrator\nnameserver 198.51.100.54\n";
    check(unlink(target) == 0, "remove owned symlink before manual replacement");
    write_file(target, text, sizeof(text) - 1);
    check(resolver.update(1, metadata(0xc0000202)) == 0 && !resolver.managed(),
          "a regular target installed during service lifetime takes precedence");
    content(target, text);
    content(generated, expected);
    resolver.close();
    check(resolver.open(store, target) == 0 && !resolver.managed(),
          "restart preserves both a replaced target and hidden recorded contents");
    content(generated, expected);

    path(runtime, "unrecorded");
    path(target, "unrecorded-link");
    path(generated, "unrecorded/resolv.conf");
    check(mkdir(runtime, 0700) == 0, "prepare an unrecorded generated-looking file");
    write_file(generated, expected, strlen(expected));
    check(symlink(generated, target) == 0, "prepare an unrecorded runtime link");
    net::Store unrecorded_store(runtime);
    net::Resolver unrecorded;
    check(unrecorded.open(unrecorded_store, target) == 0 && !unrecorded.managed() &&
              unrecorded.update(1, metadata(0xc0000203)) == 0,
          "a generated comment alone does not establish ownership");
    content(target, expected);
    puts("RESOLVER_MANUAL_TAKEOVER_PASS");
}

static void record_word(uint8_t* bytes, uint32_t value) {
    for (unsigned i = 0; i < 4; i++)
        bytes[i] = value >> (i * 8);
}

static void record_checksum(uint8_t* bytes, size_t size) {
    uint32_t checksum = 2166136261;
    for (size_t i = 16; i < size; i++)
        checksum = (checksum ^ bytes[i]) * 16777619;
    record_word(bytes + 12, checksum);
}

static void recovery() {
    char runtime[300], target[300], record[300];
    path(runtime, "recovery");
    path(target, "recovery-link");
    path(record, "recovery/resolv.owned");
    net::Store store(runtime);
    pid_t child = fork();
    check(child >= 0, "fork resolver publisher");
    if (!child) {
        net::Resolver resolver;
        check(resolver.open(store, target) == 0 && resolver.update(1, metadata(0xc0000201)) == 0,
              "publish metadata before process exit");
        _exit(0);
    }
    int status;
    check(waitpid(child, &status, 0) == child && WIFEXITED(status) && !WEXITSTATUS(status),
          "actual publisher exits without C++ cleanup");
    char expected[1024];
    snprintf(expected, sizeof(expected), "%snameserver 192.0.2.1\n", prefix);
    content(target, expected);
    uint8_t original[4096], corrupt[4096];
    size_t size = read_file(record, original, sizeof(original));
    memcpy(corrupt, original, size);
    corrupt[size - 1] ^= 1;
    write_file(record, corrupt, size);
    for (unsigned i = 0; i < 70; i++) {
        net::Resolver rejected;
        check(rejected.open(store, target) == EINVAL && rejected.update(1, metadata(1)) == EBADF,
              "corrupt ownership cannot mutate data or leak failed-open descriptions");
    }
    content(target, expected);
    write_file(record, original, 19);
    net::Resolver truncated;
    check(truncated.open(store, target) == EINVAL, "reject a truncated ownership header");
    for (unsigned kind = 0; kind < 8; kind++) {
        memcpy(corrupt, original, size);
        switch (kind) {
        case 0:
            record_word(corrupt + 16, UINT32_MAX);
            break;
        case 1:
            record_word(corrupt + 20, UINT32_MAX);
            break;
        case 2:
            corrupt[8] ^= 1;
            break;
        case 3:
            corrupt[0] ^= 1;
            break;
        case 4:
            corrupt[24] = '!';
            break;
        case 5:
            corrupt[size - 1] = 'x';
            break;
        case 6:
            corrupt[24 + sizeof(prefix)] = 0;
            break;
        case 7:
            corrupt[24 + sizeof(prefix)] = 127;
            break;
        }
        record_checksum(corrupt, size);
        write_file(record, corrupt, size);
        net::Resolver rejected;
        check(rejected.open(store, target) == EINVAL,
              "a valid checksum cannot bypass header, length, or generated-text validation");
        content(target, expected);
    }
    uint8_t overline[24 + sizeof(prefix) - 1 + 256]{};
    memcpy(overline, original, 24);
    record_word(overline + 8, sizeof(overline));
    record_word(overline + 16, 0);
    record_word(overline + 20, sizeof(overline) - 24);
    memcpy(overline + 24, prefix, sizeof(prefix) - 1);
    memset(overline + 24 + sizeof(prefix) - 1, 'a', 255);
    overline[sizeof(overline) - 1] = '\n';
    record_checksum(overline, sizeof(overline));
    write_file(record, overline, sizeof(overline));
    net::Resolver long_line;
    check(long_line.open(store, target) == EINVAL,
          "recorded output cannot exceed the complete libc line bound");
    content(target, expected);
    const char* malformed[]{"nameserver 256.0.0.1\n",
                            "nameserver 0.0.0.0\n",
                            "nameserver 192.000.2.1\n",
                            "nameserver 192.0.2.1\nnameserver 192.0.2.1\n",
                            "nameserver 192.0.2.1\nsearch UPPER.example\n",
                            "search trailing.example.\n",
                            "search ok.example\nnameserver 192.0.2.1\n",
                            "options timeout:1\n",
                            "search broken..example\n",
                            "nameserver 192.0.2.1\nnameserver 192.0.2.2\n"
                            "nameserver 192.0.2.3\nnameserver 192.0.2.4\n",
                            "search same.example same.example\n"};
    for (const char* body : malformed) {
        size_t text_size = sizeof(prefix) - 1 + strlen(body), total = 24 + text_size;
        memcpy(corrupt, original, 24);
        record_word(corrupt + 8, total);
        record_word(corrupt + 16, 0);
        record_word(corrupt + 20, text_size);
        memcpy(corrupt + 24, prefix, sizeof(prefix) - 1);
        memcpy(corrupt + 24 + sizeof(prefix) - 1, body, strlen(body));
        record_checksum(corrupt, total);
        write_file(record, corrupt, total);
        net::Resolver rejected;
        check(rejected.open(store, target) == EINVAL,
              "recorded output must have valid canonical DNS and search directives");
        content(target, expected);
    }
    write_file(record, original, size);
    net::Resolver restarted;
    check(restarted.open(store, target) == 0 && restarted.managed(),
          "recover recorded stale metadata");
    content(target, prefix);
    check(restarted.update(1, metadata(0xc0000202)) == 0, "reuse recovered publisher");
    size = read_file(record, original, sizeof(original));
    memcpy(corrupt, original, size);
    corrupt[8] ^= 1;
    write_file(record, corrupt, size);
    check(restarted.update(1, metadata(0xc0000203)) == EINVAL,
          "live update revalidates ownership before rewriting a corrupt record");
    snprintf(expected, sizeof(expected), "%snameserver 192.0.2.2\n", prefix);
    content(target, expected);
    write_file(record, original, size);
    check(restarted.withdraw(1) == 0, "repair record and withdraw owned metadata");
    content(target, prefix);
    puts("RESOLVER_PROCESS_CORRUPT_RECOVERY_PASS cycles=70 semantic=20");
}

static void publication_failure() {
    char runtime[300], target[300], generated[300], record[300];
    path(runtime, "publication");
    path(target, "publication-link");
    path(generated, "publication/resolv.conf");
    path(record, "publication/resolv.owned");
    net::Store store(runtime);
    net::Resolver resolver;
    sync_calls = 0;
    sync_failure = 1;
    int error = resolver.open(store, target);
    sync_failure = 0;
    check(error == EIO && resolver.update(1, metadata(0xc0000201)) == EBADF &&
              access(generated, F_OK) < 0 && errno == ENOENT && access(record, F_OK) < 0 &&
              errno == ENOENT,
          "failed initial target synchronization publishes no metadata or ownership");
    check(resolver.open(store, target) == 0 && resolver.update(1, metadata(0xc0000201)) == 0,
          "retry after failed link setup opens a checked publisher");
    char expected[1024];
    snprintf(expected, sizeof(expected), "%snameserver 192.0.2.1\n", prefix);
    for (unsigned phase = 1; phase <= 3; phase++) {
        rename_calls = 0;
        rename_failures = 1u << (phase - 1);
        error = resolver.update(1, metadata(0xc0000202));
        rename_failures = 0;
        check(error == EIO && rename_calls >= phase,
              "intent, data, and final ownership rename failures are reported");
        content(target, expected);
    }
    for (unsigned phase = 1; phase <= 6; phase++) {
        sync_calls = 0;
        sync_failure = phase;
        error = resolver.update(1, metadata(0xc0000202));
        sync_failure = 0;
        check(error == EIO && sync_calls >= phase,
              "file and directory synchronization failures restore prior output");
        content(target, expected);
    }
    rename_calls = 0;
    rename_failures = (1u << 2) | (1u << 3);
    error = resolver.update(1, metadata(0xc0000202));
    rename_failures = 0;
    check(error == EIO && rename_calls == 4,
          "failed publication plus failed rollback retains an ambiguous intent");
    snprintf(expected, sizeof(expected), "%snameserver 192.0.2.2\n", prefix);
    content(target, expected);
    check(resolver.update(1, metadata(0xc0000203)) == 0,
          "retry resolves pending old/new ownership before applying desired settings");
    snprintf(expected, sizeof(expected), "%snameserver 192.0.2.3\n", prefix);
    content(target, expected);
    check(resolver.withdraw(1) == 0, "withdraw retried metadata without stale contributions");
    content(target, prefix);
    puts("RESOLVER_PUBLICATION_FAILURE_PASS renames=3 syncs=6 rollback=1 link_sync=1");
}

static void partial_recovery() {
    char runtime[300], target[300], generated[300], record[300];
    path(runtime, "partial");
    path(target, "partial-link");
    path(generated, "partial/resolv.conf");
    path(record, "partial/resolv.owned");
    net::Store store(runtime);
    net::Resolver original;
    check(original.open(store, target) == 0 && original.update(1, metadata(0xc0000201)) == 0,
          "capture a committed old resolver snapshot");
    char before[1024], after[1024];
    size_t before_size = read_file(generated, before, sizeof(before));
    check(original.update(1, metadata(0xc0000202)) == 0,
          "capture a committed new resolver snapshot");
    size_t after_size = read_file(generated, after, sizeof(after));
    uint8_t committed[4096], intent[4096];
    size_t committed_size = read_file(record, committed, sizeof(committed));
    memcpy(intent, committed, 24);
    size_t intent_size = 24 + before_size + after_size;
    record_word(intent + 8, intent_size);
    record_word(intent + 16, before_size);
    record_word(intent + 20, after_size);
    memcpy(intent + 24, before, before_size);
    memcpy(intent + 24 + before_size, after, after_size);
    record_checksum(intent, intent_size);
    original.close();
    // Derive each recorded boundary from production-written snapshots, then
    // leave that actual file state across a child process exit.
    for (unsigned phase = 0; phase < 4; phase++) {
        pid_t child = fork();
        check(child >= 0, "fork interrupted resolver publisher");
        if (!child) {
            write_file(record, phase == 2 ? committed : intent,
                       phase == 2 ? committed_size : intent_size);
            if (phase == 3)
                check(unlink(generated) == 0, "leave an intent with absent generated data");
            else
                write_file(generated, phase == 0 ? before : after,
                           phase == 0 ? before_size : after_size);
            _exit(0);
        }
        int status;
        check(waitpid(child, &status, 0) == child && WIFEXITED(status) && !WEXITSTATUS(status),
              "actual child leaves old, new, committed, or missing metadata");
        net::Resolver restarted;
        check(restarted.open(store, target) == 0 && restarted.managed(),
              "restart cleans either recorded snapshot without trusting stale lease data");
        content(target, prefix);
    }
    write_file(record, intent, intent_size);
    constexpr char manual[] = "# edited after interrupted publication\nsearch manual.example\n";
    write_file(generated, manual, sizeof(manual) - 1);
    net::Resolver edited;
    check(edited.open(store, target) == 0 && !edited.managed(),
          "pending old/new records cannot claim a manually changed file");
    content(target, manual);
    puts("RESOLVER_INTENT_RECOVERY_PASS phases=4 manual=1");
}

static void permissions() {
    char runtime[300], target[300], generated[300], record[300];
    path(runtime, "permissions");
    path(target, "permissions-link");
    path(generated, "permissions/resolv.conf");
    path(record, "permissions/resolv.owned");
    net::Store store(runtime);
    net::Resolver resolver;
    directory_mode_failure = true;
    int error = resolver.open(store, target);
    check(error == EACCES && !directory_mode_failure && access(generated, F_OK) < 0 &&
              errno == ENOENT && access(record, F_OK) < 0 && errno == ENOENT,
          "failed public-directory permissions publish no inaccessible data");
    struct stat information;
    check(stat(runtime, &information) == 0 && (information.st_mode & 0777) == 0700 &&
              resolver.open(store, target) == EACCES,
          "an existing private directory keeps its mode and is rejected");
    check(chmod(runtime, 0755) == 0 && resolver.open(store, target) == 0,
          "caller can explicitly repair its dedicated public runtime directory");
    file_mode_failure = true;
    error = resolver.update(1, metadata(0xc0000201));
    check(error == EACCES && !file_mode_failure,
          "failed temporary-file permissions cannot publish unusable resolver text");
    content(target, prefix);
    check(resolver.update(1, metadata(0xc0000201)) == 0,
          "retry succeeds after the file-permission operation recovers");
    check(stat(runtime, &information) == 0 && (information.st_mode & 0777) == 0755 &&
              stat(generated, &information) == 0 && (information.st_mode & 0777) == 0644 &&
              stat(record, &information) == 0 && (information.st_mode & 0777) == 0600,
          "restrictive umask leaves public resolver text and private ownership as requested");
    check(chmod(runtime, 0777) == 0 && resolver.update(1, metadata(0xc0000202)) == EACCES,
          "an unsafe writable runtime directory cannot publish a new contribution");
    char expected[1024];
    snprintf(expected, sizeof(expected), "%snameserver 192.0.2.1\n", prefix);
    content(target, expected);
    check(chmod(runtime, 0755) == 0 && resolver.update(1, metadata(0xc0000202)) == 0,
          "restored directory policy permits pending recovery and retry");
    puts("RESOLVER_PERMISSIONS_PASS umask=077 directory=0755 text=0644 record=0600");
}

static void resource_failure(bool native) {
    char runtime[300], target[300];
    path(runtime, "resources");
    path(target, "resources-link");
    net::Store store(runtime);
    net::Resolver resolver;
    check(resolver.open(store, target) == 0 && resolver.update(1, metadata(0xc0000201)) == 0,
          "prepare checked publication pressure");
    rlimit old{};
    if (native) {
        check(getrlimit(RLIMIT_NOFILE, &old) == 0, "read native descriptor bound");
        rlimit bounded{64, old.rlim_max};
        check(setrlimit(RLIMIT_NOFILE, &bounded) == 0, "bound native fixture descriptors");
    }
    int descriptors[128];
    unsigned count = 0;
    while (count < 128) {
        int fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
        if (fd < 0)
            break;
        descriptors[count++] = fd;
    }
    check(count && count < 128 && errno == EMFILE &&
              resolver.update(1, metadata(0xc0000202)) == EMFILE,
          "exhausted file table cannot publish an unrecorded change");
    check(close(descriptors[--count]) == 0, "release one actual descriptor slot");
    char expected[1024];
    snprintf(expected, sizeof(expected), "%snameserver 192.0.2.1\n", prefix);
    content(target, expected);
    check(resolver.update(1, metadata(0xc0000202)) == 0,
          "retry completes with one available transient descriptor");
    snprintf(expected, sizeof(expected), "%snameserver 192.0.2.2\n", prefix);
    content(target, expected);
    for (unsigned i = 0; i < count; i++)
        check(close(descriptors[i]) == 0, "release fixture descriptor pressure");
    if (native)
        check(setrlimit(RLIMIT_NOFILE, &old) == 0, "restore native process descriptor bound");
    puts("RESOLVER_RESOURCE_RETRY_PASS");
}

int main(int argc, char** argv) {
    setvbuf(stdout, nullptr, _IOLBF, 0);
    mode_t old_mask = umask(077);
    snprintf(base, sizeof(base), "/tmp/axiom64-resolver-%ld", long(getpid()));
    check(mkdir(base, 0700) == 0, "create isolated fixture directory");
    merge();
    limits();
    manual();
    manual_takeover();
    recovery();
    publication_failure();
    partial_recovery();
    permissions();
    resource_failure(argc == 2 && !strcmp(argv[1], "--native"));
    umask(old_mask);
    puts("RESOLVER_TESTS_PASS");
}
