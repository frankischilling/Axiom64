// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include "protected.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/fsuid.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <unistd.h>

static int failed(int error) {
    errno = error;
    return -1;
}

static int root(void) {
    return geteuid() || getegid() || (uid_t)setfsuid(-1) || (gid_t)setfsgid(-1) ? failed(EPERM) : 0;
}

static int name_valid(const char* name) {
    size_t size = name ? strnlen(name, 256) : 0;
    if (!size || size == 256 || !strcmp(name, ".") || !strcmp(name, ".."))
        return 0;
    for (size_t i = 0; i < size; i++)
        if (!((name[i] >= 'a' && name[i] <= 'z') || (name[i] >= '0' && name[i] <= '9') ||
              name[i] == '-' || name[i] == '_' || name[i] == '.'))
            return 0;
    return 1;
}

static int directory_policy(int fd, mode_t mode, int final) {
    struct stat value;
    if (fstat(fd, &value) < 0)
        return -1;
    if (!S_ISDIR(value.st_mode) || value.st_uid || value.st_gid ||
        (final ? (value.st_mode & 07777) != mode
               : ((value.st_mode & 0022) && !(value.st_mode & S_ISVTX))))
        return failed(EACCES);
    return 0;
}

int account_directory_open(const char* path, mode_t mode, int create) {
    if (root() < 0)
        return -1;
    if ((mode != 0755 && mode != 0700) || (create != 0 && create != 1))
        return failed(EINVAL);
    size_t length = path ? strnlen(path, 4096) : 0;
    if (length < 2 || length == 4096 || path[0] != '/')
        return failed(EINVAL);
    for (size_t start = 1, end; start < length; start = end + 1) {
        end = start;
        while (end < length && path[end] != '/')
            end++;
        size_t size = end - start;
        if (!size || size > 255 || (size == 1 && path[start] == '.') ||
            (size == 2 && path[start] == '.' && path[start + 1] == '.') || end == length - 1)
            return failed(EINVAL);
    }
    int fd = open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0)
        return -1;
    int error = directory_policy(fd, 0755, 0) < 0 ? errno : 0;
    for (size_t start = 1, end; !error && start < length; start = end + 1) {
        end = start;
        while (end < length && path[end] != '/')
            end++;
        char component[256];
        memcpy(component, path + start, end - start);
        component[end - start] = 0;
        mode_t desired = end == length ? mode : 0755;
        int created = create && mkdirat(fd, component, desired) == 0;
        if (create && !created && errno != EEXIST)
            error = errno;
        int next =
            error ? -1 : openat(fd, component, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (next < 0 && !error)
            error = errno;
        if (!error && created) {
            struct stat value;
            if (fstat(next, &value) < 0)
                error = errno;
            else if (value.st_uid || value.st_gid)
                error = EACCES;
            else if (fchmod(next, desired) < 0)
                error = errno;
        }
        if (!error && directory_policy(next, mode, end == length) < 0)
            error = errno;
        if (!error && created && (fsync(next) < 0 || fsync(fd) < 0))
            error = errno;
        if (close(fd) < 0 && !error)
            error = errno;
        fd = next;
    }
    if (error) {
        if (fd >= 0)
            close(fd);
        return failed(error);
    }
    return fd;
}

static int regular_policy(int fd, mode_t mode) {
    struct stat value;
    if (fstat(fd, &value) < 0)
        return -1;
    if (!S_ISREG(value.st_mode) || value.st_uid || value.st_gid || value.st_nlink != 1 ||
        (value.st_mode & 07777) != mode)
        return failed(EACCES);
    return 0;
}

int account_executable_open(int directory, const char* name) {
    if (root() < 0)
        return -1;
    if (!name_valid(name))
        return failed(EINVAL);
    int fd = openat(directory, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0)
        return -1;
    if (regular_policy(fd, 04755) < 0) {
        int error = errno;
        close(fd);
        return failed(error);
    }
    return fd;
}

int account_file_open(int directory, const char* name, int flags, mode_t mode, int create) {
    if (root() < 0)
        return -1;
    if (!name_valid(name) || (mode != 0600 && mode != 0644) || (create != 0 && create != 1) ||
        (flags & (O_CREAT | O_TRUNC | O_EXCL)))
        return failed(EINVAL);
    int options = flags | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC;
    int fd = create ? openat(directory, name, options | O_CREAT | O_EXCL, mode) : -1;
    int created = fd >= 0;
    if (!created && (!create || errno == EEXIST))
        fd = openat(directory, name, options);
    if (fd < 0)
        return -1;
    int error = 0;
    struct stat value;
    if (created && fstat(fd, &value) < 0)
        error = errno;
    else if (created &&
             (!S_ISREG(value.st_mode) || value.st_uid || value.st_gid || value.st_nlink != 1))
        error = EACCES;
    else if (created && fchmod(fd, mode) < 0)
        error = errno;
    if (!error && regular_policy(fd, mode) < 0)
        error = errno;
    if (!error && created && (fsync(fd) < 0 || fsync(directory) < 0))
        error = errno;
    if (error) {
        close(fd);
        return failed(error);
    }
    return fd;
}

int account_file_check(int directory, const char* name, mode_t mode) {
    int fd = account_file_open(directory, name, O_RDONLY, mode, 0);
    if (fd < 0)
        return errno == ENOENT ? 0 : -1;
    return close(fd);
}

int account_nonce(unsigned char bytes[16]) {
    for (size_t used = 0; used < 16;) {
        ssize_t count = getrandom(bytes + used, 16 - used, 0);
        if (count < 0 && errno == EINTR)
            continue;
        if (count <= 0) {
            explicit_bzero(bytes, 16);
            return failed(count < 0 ? errno : EIO);
        }
        used += (size_t)count;
    }
    return 0;
}

void account_nonce_name(char output[35], char prefix, const unsigned char bytes[16]) {
    static const char digits[] = "0123456789abcdef";
    output[0] = prefix;
    output[1] = '-';
    for (size_t i = 0; i < 16; i++) {
        output[2 + i * 2] = digits[bytes[i] >> 4];
        output[3 + i * 2] = digits[bytes[i] & 15];
    }
    output[34] = 0;
}

int account_file_publish(int directory, const char* name, mode_t mode, int (*writer)(int, void*),
                         void* context) {
    if (!writer || root() < 0)
        return failed(writer ? errno : EINVAL);
    if (account_file_check(directory, name, mode) < 0)
        return -1;
    unsigned char nonce[16];
    if (account_nonce(nonce) < 0)
        return -1;
    char temporary[35];
    account_nonce_name(temporary, 't', nonce);
    int fd =
        openat(directory, temporary, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0)
        return -1;
    struct stat value;
    int error = fstat(fd, &value) < 0 ? errno : 0;
    if (!error && (!S_ISREG(value.st_mode) || value.st_uid || value.st_gid || value.st_nlink != 1))
        error = EACCES;
    if (!error && fchmod(fd, 0600) < 0)
        error = errno;
    if (!error && regular_policy(fd, 0600) < 0)
        error = errno;
    if (!error && writer(fd, context) < 0)
        error = errno;
    if (!error && (fchmod(fd, mode) < 0 || fsync(fd) < 0))
        error = errno;
    if (close(fd) < 0 && !error)
        error = errno;
    if (!error && renameat(directory, temporary, directory, name) < 0)
        error = errno;
    if (!error && fsync(directory) < 0)
        error = errno;
    if (error)
        unlinkat(directory, temporary, 0);
    return error ? failed(error) : 0;
}
