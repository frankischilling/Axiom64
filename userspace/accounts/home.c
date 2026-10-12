// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include "home.h"
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int failed(int error) {
    errno = error;
    return -1;
}

static int parent(const char* path, char name[256], int create) {
    size_t length = path ? strnlen(path, 4096) : 0;
    if (length < 2 || length == 4096 || path[0] != '/' || path[length - 1] == '/')
        return failed(EINVAL);
    for (size_t start = 1, end; start < length; start = end + 1) {
        end = start;
        while (end < length && path[end] != '/')
            end++;
        size_t size = end - start;
        if (!size || size > 255 || (size == 1 && path[start] == '.') ||
            (size == 2 && path[start] == '.' && path[start + 1] == '.'))
            return failed(EINVAL);
    }
    int fd = open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0)
        return -1;
    int error = 0;
    for (size_t start = 1, end; !error && start < length; start = end + 1) {
        struct stat value;
        if (fstat(fd, &value) < 0)
            error = errno;
        else if (!S_ISDIR(value.st_mode) || value.st_uid ||
                 ((value.st_mode & 0022) && !(value.st_mode & S_ISVTX)))
            error = EACCES;
        end = start;
        while (end < length && path[end] != '/')
            end++;
        memcpy(name, path + start, end - start);
        name[end - start] = 0;
        if (end == length)
            break;
        int created = !error && create && mkdirat(fd, name, 0755) == 0;
        if (!error && create && !created && errno != EEXIST)
            error = errno;
        if (!error && created) {
            struct stat value;
            if (fstatat(fd, name, &value, AT_SYMLINK_NOFOLLOW) < 0)
                error = errno;
            else if (!S_ISDIR(value.st_mode) || value.st_uid)
                error = EACCES;
            else if (fchmodat(fd, name, 0755, 0) < 0)
                error = errno;
        }
        int next = error ? -1 : openat(fd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (next < 0 && !error)
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

int account_home_create(const char* path, uid_t uid, gid_t gid, int* created) {
    if (!created || uid == (uid_t)-1 || gid == (gid_t)-1)
        return failed(EINVAL);
    *created = 0;
    if (geteuid() || getegid())
        return failed(EPERM);
    char name[256];
    int directory = parent(path, name, 1);
    if (directory < 0)
        return -1;
    int error = 0, fd = -1;
    if (mkdirat(directory, name, 0700) < 0)
        error = errno;
    else {
        *created = 1;
        if (fchmodat(directory, name, 0700, 0) < 0)
            error = errno;
        if (!error) {
            fd = openat(directory, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
            if (fd < 0)
                error = errno;
        }
        if (!error && (fchown(fd, uid, gid) < 0 || fchmod(fd, 0700) < 0 || fsync(fd) < 0 ||
                       fsync(directory) < 0))
            error = errno;
    }
    if (fd >= 0 && close(fd) < 0 && !error)
        error = errno;
    if (close(directory) < 0 && !error)
        error = errno;
    return error ? failed(error) : 0;
}

int account_home_rollback(const char* path, uid_t uid, gid_t gid) {
    if (geteuid() || getegid())
        return failed(EPERM);
    char name[256];
    int directory = parent(path, name, 0);
    if (directory < 0)
        return -1;
    struct stat value;
    int error = fstatat(directory, name, &value, AT_SYMLINK_NOFOLLOW) < 0 ? errno : 0;
    if (!error &&
        (!S_ISDIR(value.st_mode) || ((value.st_uid != uid || value.st_gid != gid) && value.st_uid)))
        error = EACCES;
    if (!error && unlinkat(directory, name, AT_REMOVEDIR) < 0)
        error = errno;
    if (!error && fsync(directory) < 0)
        error = errno;
    if (close(directory) < 0 && !error)
        error = errno;
    return error ? failed(error) : 0;
}
