// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define CHECK(expr)                                                                                \
    do {                                                                                           \
        if (!(expr)) {                                                                             \
            fprintf(stderr, "EXT2_FAIL line=%d: %s errno=%d (%s)\n", __LINE__, #expr, errno,       \
                    strerror(errno));                                                              \
            exit(1);                                                                               \
        }                                                                                          \
    } while (0)
#define ERROR(expr, code)                                                                          \
    do {                                                                                           \
        errno = 0;                                                                                 \
        CHECK((expr) == -1 && errno == (code));                                                    \
    } while (0)
static const char* volume = "/tmp/ext2-volume";
static unsigned char bytes[4096], actual[4096];
static unsigned block_size;
static uint64_t pattern_length, triple_offset;

static void geometry(void) {
    struct statfs fs;
    CHECK(statfs(volume, &fs) == 0 && fs.f_type == 0xef53);
    CHECK(fs.f_bsize == 1024 || fs.f_bsize == 2048 || fs.f_bsize == 4096);
    CHECK(fs.f_blocks && fs.f_bfree <= fs.f_blocks && fs.f_ffree <= fs.f_files);
    block_size = fs.f_bsize;
    uint64_t n = block_size / 4;
    pattern_length = (12 + n + 3) * block_size + 713;
    triple_offset = (12 + n + n * n) * block_size + 29;
}
static void put(const char* path, const char* text) {
    int fd = open(path, O_CREAT | O_TRUNC | O_WRONLY, 0644);
    CHECK(fd >= 0 && write(fd, text, strlen(text)) == (ssize_t)strlen(text) && close(fd) == 0);
}
static void expect(int fd, const char* text) {
    char buffer[128] = {0};
    CHECK(fd >= 0 && read(fd, buffer, sizeof(buffer)) == (ssize_t)strlen(text));
    CHECK(!strcmp(buffer, text) && close(fd) == 0);
}
static void pattern(int fd, int write_it, uint64_t length, uint64_t start) {
    for (uint64_t offset = 0; offset < length;) {
        size_t count = length - offset < sizeof(bytes) ? length - offset : sizeof(bytes);
        for (size_t i = 0; i < count; i++)
            bytes[i] = ((offset + i) * 31 + 17) & 255;
        if (write_it)
            CHECK(pwrite(fd, bytes, count, start + offset) == (ssize_t)count);
        else {
            CHECK(pread(fd, actual, count, start + offset) == (ssize_t)count);
            CHECK(!memcmp(actual, bytes, count));
        }
        offset += count;
    }
}
static void copy_program(const char* source, const char* target) {
    int in = open(source, O_RDONLY), out = open(target, O_CREAT | O_TRUNC | O_WRONLY, 0755);
    CHECK(in >= 0 && out >= 0);
    ssize_t count;
    while ((count = read(in, bytes, sizeof(bytes))) > 0)
        CHECK(write(out, bytes, count) == count);
    CHECK(count == 0 && fsync(out) == 0 && close(out) == 0 && close(in) == 0);
    pid_t child = fork();
    CHECK(child >= 0);
    if (!child) {
        execl(target, target, "child", (char*)NULL);
        _exit(99);
    }
    int status;
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 17);
}
static void long_name(unsigned i, char* path) {
    int prefix = sprintf(path, "/tmp/ext2-volume/many/%03u-", i);
    memset(path + prefix, 'a' + i % 26, 236);
    path[prefix + 236] = 0;
}
static void namespace_tests(void) {
    CHECK(mkdir("/tmp/ext2-volume/a", 0755) == 0);
    CHECK(mkdir("/tmp/ext2-volume/b", 0755) == 0);
    CHECK(mkdir("/tmp/ext2-volume/a/sub", 0755) == 0);
    put("/tmp/ext2-volume/a/file", "linked-data");
    int fd = open("/tmp/ext2-volume/a/file", O_RDWR);
    CHECK(fd >= 0);
    CHECK(link("/tmp/ext2-volume/a/file", "/tmp/ext2-volume/a/alias") == 0);
    CHECK(unlink("/tmp/ext2-volume/a/file") == 0);
    CHECK(rename("/tmp/ext2-volume/a/alias", "/tmp/ext2-volume/final") == 0);
    struct stat stat;
    CHECK(fstat(fd, &stat) == 0 && stat.st_nlink == 1 && stat.st_size == 11);
    ERROR(link("/tmp/ext2-volume/final", "/tmp/ext2-cross"), EXDEV);
    ERROR(rename("/tmp/ext2-volume/final", "/tmp/ext2-cross"), EXDEV);
    CHECK(close(fd) == 0);
    put("/tmp/ext2-volume/old", "old-data");
    int old = open("/tmp/ext2-volume/old", O_RDONLY);
    CHECK(old >= 0 && rename("/tmp/ext2-volume/final", "/tmp/ext2-volume/old") == 0);
    expect(old, "old-data");
    CHECK(rename("/tmp/ext2-volume/old", "/tmp/ext2-volume/final") == 0);
    fd = open("/tmp/ext2-volume/final", O_RDONLY);
    CHECK(fd >= 0 && fsync(fd) == 0 && close(fd) == 0);
    CHECK(rename("/tmp/ext2-volume/a/sub", "/tmp/ext2-volume/b/sub") == 0);
    CHECK(chdir("/tmp/ext2-volume/b/sub/..") == 0);
    char cwd[256];
    CHECK(getcwd(cwd, sizeof(cwd)) == cwd && !strcmp(cwd, "/tmp/ext2-volume/b"));
    CHECK(chdir("/") == 0);
    CHECK(rmdir("/tmp/ext2-volume/b/sub") == 0);
    CHECK(rmdir("/tmp/ext2-volume/a") == 0 && rmdir("/tmp/ext2-volume/b") == 0);
    CHECK(symlink("final", "/tmp/ext2-volume/short-link") == 0);
    char target[128] = {0};
    for (unsigned i = 0; i < 50; i++)
        strcat(target, "./");
    strcat(target, "final");
    CHECK(symlink(target, "/tmp/ext2-volume/long-link") == 0);
    char link_text[128] = {0};
    CHECK(readlink("/tmp/ext2-volume/long-link", link_text, sizeof(link_text)) ==
          (ssize_t)strlen(target));
    CHECK(!strcmp(link_text, target));
    expect(open("/tmp/ext2-volume/long-link", O_RDONLY), "linked-data");
    CHECK(mkdir("/tmp/ext2-volume/many", 0755) == 0);
    for (unsigned i = 0; i < 192; i++) {
        char path[320];
        long_name(i, path);
        fd = open(path, O_CREAT | O_WRONLY | O_EXCL, 0600);
        CHECK(fd >= 0 && close(fd) == 0);
    }
    DIR* dir = opendir("/tmp/ext2-volume/many");
    CHECK(dir);
    unsigned count = 0;
    struct dirent* entry;
    while ((entry = readdir(dir))) {
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))
            continue;
        CHECK(strlen(entry->d_name) == 240 && entry->d_type == DT_REG);
        count++;
    }
    CHECK(count == 192 && closedir(dir) == 0);
    char path[320];
    long_name(77, path);
    CHECK(unlink(path) == 0);
    ERROR(rmdir("/tmp/ext2-volume/many"), ENOTEMPTY);
    char maxname[300] = "/tmp/ext2-volume/";
    size_t prefix = strlen(maxname);
    memset(maxname + prefix, 'z', 255);
    maxname[prefix + 255] = 0;
    put(maxname, "long-name");
    ERROR(umount(volume), EBUSY); // The next open inode keeps its volume mounted.
}
static void write_tests(void) {
    int raw = open("/dev/vda", O_RDWR);
    CHECK(raw >= 0);
    CHECK(mount("/dev/vda", volume, "ext2", 0, NULL) == 0);
    geometry();
    expect(open("/tmp/ext2-volume/seed.txt", O_RDONLY), "host-created seed\n");
    ERROR(open("/dev/vda", O_WRONLY), EBUSY);
    ERROR(pwrite(raw, "x", 1, 8192), EBUSY);
    CHECK(close(raw) == 0);
    CHECK(mkdir("/tmp/ext2-second", 0755) == 0);
    ERROR(mount("/dev/vda", "/tmp/ext2-second", "ext2", 0, NULL), EBUSY);
    struct statfs before, after;
    CHECK(statfs(volume, &before) == 0);
    CHECK(mkdir("/tmp/ext2-volume/pinned-parent", 0755) == 0);
    CHECK(mkdir("/tmp/ext2-volume/pinned-parent/child", 0755) == 0);
    int child_dir = open("/tmp/ext2-volume/pinned-parent/child", O_RDONLY | O_DIRECTORY);
    CHECK(child_dir >= 0);
    CHECK(rmdir("/tmp/ext2-volume/pinned-parent/child") == 0);
    CHECK(rmdir("/tmp/ext2-volume/pinned-parent") == 0);
    ERROR(mount(NULL, volume, NULL, MS_REMOUNT | MS_RDONLY, NULL), EBUSY);
    CHECK(fchdir(child_dir) == 0 && chdir("..") == 0);
    CHECK(chdir("/") == 0 && close(child_dir) == 0);
    int pin = open(volume, O_RDONLY | O_DIRECTORY);
    CHECK(pin >= 0);
    CHECK(fsync(pin) == 0);
    CHECK(statfs(volume, &after) == 0 && after.f_bfree == before.f_bfree &&
          after.f_ffree == before.f_ffree);
    namespace_tests();
    CHECK(close(pin) == 0);
    int fd = open("/tmp/ext2-volume/pattern", O_CREAT | O_RDWR, 0644);
    CHECK(fd >= 0);
    pattern(fd, 1, pattern_length, 37);
    pattern(fd, 0, pattern_length, 37);
    void* mapping = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    CHECK(mapping != MAP_FAILED && ((unsigned char*)mapping)[37] == 17);
    ((unsigned char*)mapping)[37] = 0;
    CHECK(pread(fd, actual, 1, 37) == 1 && actual[0] == 17);
    CHECK(munmap(mapping, 4096) == 0);
    errno = 0;
    CHECK(mmap(NULL, 4096, PROT_READ, MAP_SHARED, fd, 0) == MAP_FAILED && errno == ENODEV);
    CHECK(fsync(fd) == 0 && close(fd) == 0);
    fd = open("/tmp/ext2-volume/trim", O_CREAT | O_RDWR, 0644);
    CHECK(fd >= 0);
    pattern(fd, 1, pattern_length, 0);
    uint64_t keep = 12 * block_size + 37;
    CHECK(ftruncate(fd, keep) == 0 && ftruncate(fd, pattern_length) == 0);
    CHECK(pread(fd, actual, sizeof(actual), keep) == sizeof(actual));
    for (unsigned i = 0; i < sizeof(actual); i++)
        CHECK(!actual[i]);
    CHECK(fstat(fd, &(struct stat){0}) == 0 && close(fd) == 0);
    fd = open("/tmp/ext2-volume/sparse", O_CREAT | O_RDWR, 0644);
    CHECK(fd >= 0 && pwrite(fd, "triples!", 8, triple_offset) == 8);
    struct stat stat;
    CHECK(fstat(fd, &stat) == 0 && (uint64_t)stat.st_size == triple_offset + 8);
    CHECK(stat.st_blocks == (long)(4 * block_size / 512));
    CHECK(pread(fd, actual, sizeof(actual), triple_offset - sizeof(actual)) == sizeof(actual));
    for (unsigned i = 0; i < sizeof(actual); i++)
        CHECK(!actual[i]);
    CHECK(fsync(fd) == 0 && close(fd) == 0);
    fd = open("/tmp/ext2-volume/pruned", O_CREAT | O_RDWR, 0644);
    CHECK(fd >= 0 && pwrite(fd, "triples!", 8, triple_offset) == 8 && ftruncate(fd, 0) == 0);
    CHECK(fstat(fd, &stat) == 0 && !stat.st_size && !stat.st_blocks);
    CHECK(write(fd, "tiny", 4) == 4 && close(fd) == 0);
    copy_program("/bin/abi-static", "/tmp/ext2-volume/program-static");
    copy_program("/bin/abi-dynamic", "/tmp/ext2-volume/program-dynamic");
    put("/tmp/ext2-volume/old-time", "dated");
    const struct timespec old_times[2] = {{-123456789, 0}, {-42, 0}};
    CHECK(utimensat(AT_FDCWD, "/tmp/ext2-volume/old-time", old_times, 0) == 0);
    const struct timespec future_times[2] = {{2147483648LL, 0}, {2147483648LL, 0}};
    ERROR(utimensat(AT_FDCWD, "/tmp/ext2-volume/old-time", future_times, 0), EINVAL);
    put("/tmp/ext2-volume/orphan", "still-open");
    fd = open("/tmp/ext2-volume/orphan", O_RDONLY);
    CHECK(fd >= 0 && unlink("/tmp/ext2-volume/orphan") == 0);
    ERROR(mount(NULL, volume, NULL, MS_REMOUNT | MS_RDONLY, NULL), EBUSY);
    expect(fd, "still-open");
    CHECK(chmod("/tmp/ext2-volume/final", 0640) == 0);
    const struct timespec times[2] = {{1234567890, 0}, {1234567891, 0}};
    CHECK(utimensat(AT_FDCWD, "/tmp/ext2-volume/final", times, 0) == 0);
    CHECK(mount(NULL, volume, NULL, MS_REMOUNT | MS_RDONLY, NULL) == 0);
    ERROR(open("/tmp/ext2-volume/final", O_WRONLY), EROFS);
    CHECK(mount(NULL, volume, NULL, MS_REMOUNT, NULL) == 0);
    CHECK(umount(volume) == 0);
    raw = open("/dev/vda", O_RDWR);
    CHECK(raw >= 0 && close(raw) == 0);
    puts("EXT2_WRITE_PASS");
}
static void verify_tests(int readonly_disk) {
    if (readonly_disk)
        ERROR(mount("/dev/vda", volume, "ext2", 0, NULL), EROFS);
    CHECK(mount("/dev/vda", volume, "ext2", MS_RDONLY, NULL) == 0);
    geometry();
    expect(open("/tmp/ext2-volume/seed.txt", O_RDONLY), "host-created seed\n");
    expect(open("/tmp/ext2-volume/cli.txt", O_RDONLY), "command-line-mount\n");
    struct stat info;
    CHECK(stat("/tmp/ext2-volume/final", &info) == 0 && (info.st_mode & 07777) == 0640 &&
          info.st_nlink == 1);
    CHECK(info.st_atim.tv_sec == 1234567890 && info.st_mtim.tv_sec == 1234567891);
    CHECK(stat("/tmp/ext2-volume/old-time", &info) == 0);
    CHECK(info.st_atim.tv_sec == -123456789 && info.st_mtim.tv_sec == -42);
    ERROR(open("/tmp/ext2-volume/orphan", O_RDONLY), ENOENT);
    expect(open("/tmp/ext2-volume/short-link", O_RDONLY), "linked-data");
    expect(open("/tmp/ext2-volume/long-link", O_RDONLY), "linked-data");
    int fd = open("/tmp/ext2-volume/pattern", O_RDONLY);
    CHECK(fd >= 0 && fstat(fd, &info) == 0 && (uint64_t)info.st_size == 37 + pattern_length);
    pattern(fd, 0, pattern_length, 37);
    CHECK(close(fd) == 0);
    fd = open("/tmp/ext2-volume/sparse", O_RDONLY);
    CHECK(fd >= 0 && pread(fd, actual, 8, triple_offset) == 8 && !memcmp(actual, "triples!", 8));
    CHECK(fstat(fd, &info) == 0 && (uint64_t)info.st_size == triple_offset + 8);
    CHECK(close(fd) == 0);
    expect(open("/tmp/ext2-volume/pruned", O_RDONLY), "tiny");
    DIR* dir = opendir("/tmp/ext2-volume/many");
    CHECK(dir);
    unsigned count = 0;
    struct dirent* entry;
    while ((entry = readdir(dir)))
        if (entry->d_name[0] != '.')
            count++;
    CHECK(count == 191 && closedir(dir) == 0);
    ERROR(open("/tmp/ext2-volume/new", O_CREAT | O_RDWR, 0644), EROFS);
    ERROR(chmod("/tmp/ext2-volume/final", 0666), EROFS);
    ERROR(unlink("/tmp/ext2-volume/final"), EROFS);
    ERROR(mkdir("/tmp/ext2-volume/no", 0755), EROFS);
    ERROR(rename("/tmp/ext2-volume/final", "/tmp/ext2-volume/no"), EROFS);
    ERROR(link("/tmp/ext2-volume/final", "/tmp/ext2-volume/no"), EROFS);
    ERROR(truncate("/tmp/ext2-volume/final", 0), EROFS);
    if (readonly_disk)
        ERROR(mount(NULL, volume, NULL, MS_REMOUNT, NULL), EROFS);
    CHECK(umount(volume) == 0);
    puts(readonly_disk ? "EXT2_READONLY_PASS" : "EXT2_REBOOT_PASS");
}
static void invalid_tests(void) {
    unsigned count = 0;
    for (char disk = 'a'; disk <= 'h'; disk++) {
        char path[] = "/dev/vda";
        path[7] = disk;
        int fd = open(path, O_RDONLY);
        if (fd < 0) {
            CHECK(errno == ENOENT);
            break;
        }
        char header[96] = {0};
        CHECK(pread(fd, header, sizeof(header) - 1, 0) == sizeof(header) - 1 && close(fd) == 0);
        int expected = 0;
        CHECK(sscanf(header, "AXIOM64_EXT2_EXPECT=%d", &expected) == 1 && expected > 0);
        ERROR(mount(path, volume, "ext2", 0, NULL), expected);
        ERROR(mount(path, volume, "ext2", MS_RDONLY, NULL), expected);
        count++;
    }
    CHECK(count > 0);
    printf("EXT2_REJECT_PASS volumes=%u\n", count);
}
static void error_tests(void) {
    for (char disk = 'a'; disk <= 'c'; disk++) {
        char device[] = "/dev/vda";
        device[7] = disk;
        CHECK(mount(device, volume, "ext2", disk == 'a' ? MS_RDONLY : 0, NULL) == 0);
        int fd = open("/tmp/ext2-volume/error-blob", disk == 'a' ? O_RDONLY : O_RDWR);
        CHECK(fd >= 0);
        if (disk == 'a') {
            ERROR(pread(fd, actual, 1, 0), EIO);
            CHECK(pread(fd, actual, 1, 0) == 1 && actual[0] == 0x6e);
        } else {
            ERROR(pwrite(fd, "X", 1, 5), EIO);
            CHECK(fsync(fd) == 0 && fdatasync(fd) == 0);
            CHECK(pread(fd, actual, 1, 5) == 1 && actual[0] == 'X');
        }
        CHECK(close(fd) == 0 && umount(volume) == 0);
    }
    ERROR(mount("/dev/vdd", volume, "ext2", 0, NULL), EUCLEAN);
    CHECK(mount("/dev/vdd", volume, "ext2", MS_RDONLY, NULL) == 0);
    ERROR(mount(NULL, volume, NULL, MS_REMOUNT, NULL), EUCLEAN);
    expect(open("/tmp/ext2-volume/seed.txt", O_RDONLY), "host-created seed\n");
    CHECK(umount(volume) == 0);
    ERROR(mount("/dev/vde", volume, "ext2", 0, NULL), EIO);
    ERROR(mount("/dev/vde", volume, "ext2", MS_RDONLY, NULL), EIO);
    puts("EXT2_BACKEND_ERROR_PASS");
}
static void full_tests(void) {
    CHECK(mount("/dev/vda", volume, "ext2", 0, NULL) == 0);
    geometry();
    struct statfs before, full, after;
    CHECK(statfs(volume, &before) == 0);
    int fd = open("/tmp/ext2-volume/full", O_CREAT | O_RDWR, 0644);
    CHECK(fd >= 0);
    memset(bytes, 0x59, sizeof(bytes));
    ssize_t count;
    uint64_t written = 0;
    while ((count = write(fd, bytes, sizeof(bytes))) > 0)
        written += count;
    CHECK(count == -1 && errno == ENOSPC && written > 0);
    struct stat stat;
    CHECK(fstat(fd, &stat) == 0 && (uint64_t)stat.st_size == written);
    int tail = open("/tmp/ext2-volume/last-blocks", O_CREAT | O_WRONLY, 0644);
    CHECK(tail >= 0);
    while ((count = write(tail, bytes, block_size)) > 0)
        CHECK(count == (ssize_t)block_size);
    CHECK(count == -1 && errno == ENOSPC && close(tail) == 0);
    CHECK(statfs(volume, &full) == 0 && !full.f_bfree);
    ERROR(mkdir("/tmp/ext2-volume/fail-dir", 0755), ENOSPC);
    CHECK(statfs(volume, &after) == 0 && after.f_ffree == full.f_ffree &&
          after.f_bfree == full.f_bfree);
    CHECK(close(fd) == 0 && unlink("/tmp/ext2-volume/full") == 0 &&
          unlink("/tmp/ext2-volume/last-blocks") == 0);
    CHECK(statfs(volume, &after) == 0 && after.f_bfree == before.f_bfree &&
          after.f_ffree == before.f_ffree);
    expect(open("/tmp/ext2-volume/seed.txt", O_RDONLY), "host-created seed\n");
    CHECK(umount(volume) == 0);
    CHECK(mount("/dev/vdb", volume, "ext2", 0, NULL) == 0);
    CHECK(statfs(volume, &before) == 0);
    unsigned created = 0;
    for (; created < 256; created++) {
        char path[80];
        sprintf(path, "/tmp/ext2-volume/inode-%u", created);
        fd = open(path, O_CREAT | O_WRONLY | O_EXCL, 0644);
        if (fd < 0) {
            CHECK(errno == ENOSPC);
            break;
        }
        CHECK(close(fd) == 0);
    }
    CHECK(created > 0 && created < 256 && statfs(volume, &full) == 0 && !full.f_ffree);
    for (unsigned i = 0; i < created; i++) {
        char path[80];
        sprintf(path, "/tmp/ext2-volume/inode-%u", i);
        CHECK(unlink(path) == 0);
    }
    CHECK(statfs(volume, &after) == 0 && after.f_ffree == before.f_ffree &&
          after.f_bfree == before.f_bfree);
    CHECK(umount(volume) == 0);
    puts("EXT2_FULL_VOLUME_PASS");
}
int main(int argc, char** argv) {
    CHECK(argc == 2 && mkdir(volume, 0755) == 0);
    const char* phase = argv[1];
    if (!strcmp(phase, "write"))
        write_tests();
    else if (!strcmp(phase, "verify"))
        verify_tests(0);
    else if (!strcmp(phase, "readonly"))
        verify_tests(1);
    else if (!strcmp(phase, "invalid"))
        invalid_tests();
    else if (!strcmp(phase, "error"))
        error_tests();
    else if (!strcmp(phase, "full"))
        full_tests();
    else
        CHECK(0);
    printf("EXT2_PHASE_PASS phase=%s\n", phase);
    return 0;
}
