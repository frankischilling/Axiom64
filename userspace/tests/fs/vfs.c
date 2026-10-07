// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define CHECK(expr) do { if (!(expr)) { \
    fprintf(stderr, "VFS_FAIL line=%d: %s errno=%d (%s)\n", __LINE__, #expr, errno, strerror(errno)); \
    exit(1); } } while (0)
#define ERROR(expr, code) do { errno = 0; CHECK((expr) == -1 && errno == (code)); } while (0)
static const char* volume = "/tmp/vfs-volume";
static void put(const char* path, const char* text) {
    int fd = open(path, O_CREAT | O_TRUNC | O_RDWR, 0644);
    CHECK(fd >= 0);
    CHECK(write(fd, text, strlen(text)) == (ssize_t)strlen(text));
    CHECK(close(fd) == 0);
}
static void expect_fd(int fd, const char* text) {
    char buffer[80] = {0};
    CHECK(fd >= 0);
    CHECK(read(fd, buffer, sizeof(buffer)) == (ssize_t)strlen(text));
    CHECK(!strcmp(buffer, text));
    CHECK(close(fd) == 0);
}
static void check_cwd(const char* path) {
    char buffer[1024];
    CHECK(getcwd(buffer, sizeof(buffer)) == buffer);
    CHECK(!strcmp(buffer, path));
}
static void copy_program(const char* from, const char* to) {
    int source = open(from, O_RDONLY), target = open(to, O_CREAT | O_WRONLY, 0755);
    CHECK(source >= 0 && target >= 0);
    char bytes[4096];
    ssize_t count;
    while ((count = read(source, bytes, sizeof(bytes))) > 0)
        CHECK(write(target, bytes, count) == count);
    CHECK(count == 0 && close(source) == 0 && close(target) == 0);
    pid_t child = fork();
    CHECK(child >= 0);
    if (!child) {
        execl(to, to, "child", (char*)NULL);
        _exit(99);
    }
    int status;
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 17);
}
int main(void) {
    ERROR(mkdir("/", 0755), EEXIST);
    ERROR(mkdir("/tmp/.", 0755), EEXIST);
    CHECK(mkdir(volume, 0755) == 0);
    put("/tmp/vfs-volume/hidden", "underlying");
    int covered = open(volume, O_RDONLY | O_DIRECTORY);
    CHECK(covered >= 0);
    struct stat root, mounted;
    CHECK(stat("/tmp", &root) == 0);
    ERROR(mount("none", volume, "unknown", 0, NULL), ENODEV);
    ERROR(mount("none", volume, "ramfs", MS_BIND, NULL), EINVAL);
    ERROR(mount("none", "/tmp/vfs-volume/hidden", "ramfs", 0, NULL), ENOTDIR);
    CHECK(mount("none", volume, "ramfs", 0, NULL) == 0);
    CHECK(stat(volume, &mounted) == 0 && mounted.st_dev != root.st_dev);
    ERROR(mount("none", volume, "ramfs", 0, NULL), EBUSY);
    ERROR(open("/tmp/vfs-volume/hidden", O_RDONLY), ENOENT);
    expect_fd(openat(covered, "hidden", O_RDONLY), "underlying");
    CHECK(fchdir(covered) == 0);
    expect_fd(open("hidden", O_RDONLY), "underlying");
    CHECK(chdir("/") == 0);
    CHECK(close(covered) == 0);
    int dir = open(volume, O_RDONLY | O_DIRECTORY);
    CHECK(dir >= 0);
    CHECK(mkdirat(dir, "a", 0755) == 0);
    CHECK(mkdirat(dir, "a/b", 0755) == 0);
    CHECK(symlinkat("a/b", dir, "shortcut") == 0);
    CHECK(chdir("/tmp/vfs-volume/shortcut/..") == 0);
    check_cwd("/tmp/vfs-volume/a");
    CHECK(chdir("..") == 0);
    check_cwd(volume);
    CHECK(chdir("..") == 0);
    check_cwd("/tmp");
    CHECK(chdir("/") == 0);
    put("/tmp/vfs-volume/file", "mounted");
    ERROR(openat(-1, "file", O_RDONLY), EBADF);
    expect_fd(openat(-1, "/tmp/vfs-volume/file", O_RDONLY), "mounted");
    int fd = openat(dir, "file", O_RDWR);
    CHECK(fd >= 0);
    ERROR(ftruncate(fd, -1), EINVAL);
    ERROR(ftruncate(fd, 256 * 1024 * 1024 + 1), EFBIG);
    CHECK(ftruncate(fd, 20) == 0);
    CHECK(ftruncate(fd, 7) == 0);
    CHECK(fsync(fd) == 0 && fdatasync(fd) == 0);
    ERROR(link("/tmp/vfs-volume/file", "/tmp/vfs-cross-link"), EXDEV);
    ERROR(rename("/tmp/vfs-volume/file", "/tmp/vfs-cross-rename"), EXDEV);
    CHECK(linkat(dir, "file", dir, "alias", 0) == 0);
    CHECK(unlinkat(dir, "file", 0) == 0);
    expect_fd(fd, "mounted");
    CHECK(renameat(dir, "alias", dir, "renamed") == 0);
    expect_fd(openat(dir, "renamed", O_RDONLY), "mounted");
    put("/tmp/vfs-volume/replaced", "old");
    fd = openat(dir, "replaced", O_RDONLY);
    CHECK(renameat(dir, "renamed", dir, "replaced") == 0);
    expect_fd(fd, "old");
    expect_fd(openat(dir, "replaced", O_RDONLY), "mounted");
    ERROR(renameat(dir, "a", dir, "a/b/inside"), EINVAL);
    ERROR(unlinkat(dir, "a", AT_REMOVEDIR), ENOTEMPTY);
    ERROR(rmdir(volume), EBUSY);
    CHECK(symlinkat("loop", dir, "loop") == 0);
    ERROR(openat(dir, "loop", O_RDONLY), ELOOP);
    CHECK(symlinkat("/tmp/vfs-volume/replaced", dir, "absolute") == 0);
    expect_fd(openat(dir, "absolute", O_RDONLY), "mounted");
    char target_text[80] = {0};
    CHECK(readlinkat(dir, "shortcut", target_text, sizeof(target_text)) == 3 && !strcmp(target_text, "a/b"));
    ERROR(openat(dir, "replaced/", O_RDONLY), ENOTDIR);
    char long_name[256];
    memset(long_name, 'n', 255);
    long_name[255] = 0;
    fd = openat(dir, long_name, O_CREAT | O_RDWR, 0600);
    CHECK(fd >= 0 && close(fd) == 0);
    DIR* stream = fdopendir(dup(dir));
    CHECK(stream);
    unsigned entries = 0;
    int found_long = 0;
    for (struct dirent* entry; (entry = readdir(stream));) {
        entries++;
        if (!strcmp(entry->d_name, long_name))
            found_long = 1;
        CHECK(strcmp(entry->d_name, "hidden"));
    }
    CHECK(entries >= 8 && found_long);
    CHECK(closedir(stream) == 0);
    ERROR(umount(volume), EBUSY);
    CHECK(close(dir) == 0);
    copy_program("/bin/abi-static", "/tmp/vfs-volume/static");
    copy_program("/bin/abi-dynamic", "/tmp/vfs-volume/dynamic");
    int listener = socket(AF_UNIX, SOCK_STREAM, 0);
    CHECK(listener >= 0);
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    strcpy(address.sun_path, "/tmp/vfs-volume/socket");
    CHECK(bind(listener, (struct sockaddr*)&address, sizeof(address)) == 0);
    CHECK(listen(listener, 1) == 0);
    ERROR(umount(volume), EBUSY);
    int client = socket(AF_UNIX, SOCK_STREAM, 0);
    CHECK(client >= 0);
    CHECK(connect(client, (struct sockaddr*)&address, sizeof(address)) == 0);
    int accepted = accept(listener, NULL, NULL);
    CHECK(accepted >= 0);
    CHECK(close(listener) == 0);
    ERROR(umount(volume), EBUSY);
    CHECK(close(accepted) == 0 && close(client) == 0);
    CHECK(unlink(address.sun_path) == 0);
    fd = open("/tmp/vfs-volume/replaced", O_RDWR);
    CHECK(fd >= 0);
    ERROR(mount(NULL, volume, NULL, MS_REMOUNT | MS_RDONLY, NULL), EBUSY);
    CHECK(close(fd) == 0);
    CHECK(mount(NULL, volume, NULL, MS_REMOUNT | MS_RDONLY, NULL) == 0);
    struct statfs filesystem;
    CHECK(statfs(volume, &filesystem) == 0);
    CHECK((unsigned long)filesystem.f_type == 0x858458f6ul && (filesystem.f_flags & ST_RDONLY));
    expect_fd(open("/tmp/vfs-volume/replaced", O_RDONLY), "mounted");
    ERROR(open("/tmp/vfs-volume/replaced", O_RDWR), EROFS);
    ERROR(open("/tmp/vfs-volume/new", O_CREAT | O_WRONLY, 0644), EROFS);
    ERROR(truncate("/tmp/vfs-volume/replaced", 0), EROFS);
    ERROR(mkdir("/tmp/vfs-volume/new-dir", 0755), EROFS);
    ERROR(unlink("/tmp/vfs-volume/replaced"), EROFS);
    ERROR(rename("/tmp/vfs-volume/replaced", "/tmp/vfs-volume/new"), EROFS);
    ERROR(link("/tmp/vfs-volume/replaced", "/tmp/vfs-volume/new"), EROFS);
    ERROR(symlink("replaced", "/tmp/vfs-volume/new"), EROFS);
    ERROR(chmod("/tmp/vfs-volume/replaced", 0600), EROFS);
    ERROR(utimensat(AT_FDCWD, "/tmp/vfs-volume/replaced", NULL, 0), EROFS);
    listener = socket(AF_UNIX, SOCK_STREAM, 0);
    CHECK(listener >= 0);
    ERROR(bind(listener, (struct sockaddr*)&address, sizeof(address)), EROFS);
    CHECK(close(listener) == 0);
    fd = open("/tmp/vfs-volume/replaced", O_RDONLY);
    CHECK(fd >= 0);
    CHECK(fstatfs(fd, &filesystem) == 0 && (filesystem.f_flags & ST_RDONLY));
    char* private_map = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    CHECK(private_map != MAP_FAILED && !memcmp(private_map, "mounted", 7));
    private_map[0] = 'p';
    CHECK(munmap(private_map, 4096) == 0);
    char* map = mmap(NULL, 4096, PROT_READ, MAP_SHARED, fd, 0);
    CHECK(map != MAP_FAILED && !memcmp(map, "mounted", 7));
    CHECK(close(fd) == 0);
    ERROR(mprotect(map, 4096, PROT_READ | PROT_WRITE), EACCES);
    ERROR(umount(volume), EBUSY);
    CHECK(munmap(map, 4096) == 0);
    CHECK(mount(NULL, volume, NULL, MS_REMOUNT, NULL) == 0);
    fd = open("/tmp/vfs-volume/replaced", O_RDWR);
    CHECK(fd >= 0);
    map = mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    CHECK(map != MAP_FAILED);
    ERROR(ftruncate(fd, 65537), EBUSY);
    CHECK(close(fd) == 0);
    map[0] = 'M';
    ERROR(umount(volume), EBUSY);
    CHECK(munmap(map, 4096) == 0);
    expect_fd(open("/tmp/vfs-volume/replaced", O_RDONLY), "Mounted");
    CHECK(mkdir("/tmp/vfs-volume/child", 0755) == 0);
    CHECK(mount("none", "/tmp/vfs-volume/child", "ramfs", MS_RDONLY, NULL) == 0);
    ERROR(umount(volume), EBUSY);
    ERROR(open("/tmp/vfs-volume/child/file", O_CREAT | O_WRONLY, 0600), EROFS);
    CHECK(umount("/tmp/vfs-volume/child") == 0);
    CHECK(chdir(volume) == 0);
    ERROR(umount(volume), EBUSY);
    pid_t child = fork();
    CHECK(child >= 0);
    if (!child) {
        usleep(80000);
        _exit(0);
    }
    CHECK(chdir("/") == 0);
    ERROR(umount(volume), EBUSY);
    int status;
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    CHECK(umount(volume) == 0);
    expect_fd(open("/tmp/vfs-volume/hidden", O_RDONLY), "underlying");
    ERROR(umount(volume), EINVAL);
    // A reused mount slot must not retain contents, identity, or policy.
    for (unsigned i = 0; i < 24; i++) {
        CHECK(mount("none", volume, "ramfs", 0, NULL) == 0);
        CHECK(stat(volume, &root) == 0 && root.st_dev != mounted.st_dev);
        ERROR(open("/tmp/vfs-volume/replaced", O_RDONLY), ENOENT);
        put("/tmp/vfs-volume/reuse", "new");
        CHECK(umount(volume) == 0);
    }
    CHECK(unlink("/tmp/vfs-volume/hidden") == 0 && rmdir(volume) == 0);
    sync();
    puts("VFS_TESTS_PASS");
    return 0;
}
