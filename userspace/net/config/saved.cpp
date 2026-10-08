// SPDX-License-Identifier: GPL-3.0-or-later
#include "net/config/saved.hpp"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

namespace ax::net::saved {
namespace {
int finish(int fd, int error = 0) {
    return close(fd) < 0 && !error ? errno : error;
}

int directory_policy(int fd, bool final) {
    struct stat value;
    if (fstat(fd, &value) < 0)
        return errno;
    if (!S_ISDIR(value.st_mode))
        return ENOTDIR;
    uid_t owner = geteuid();
    if (final)
        return value.st_uid == owner && (value.st_mode & 07777) == 0700 ? 0 : EACCES;
    return (value.st_uid != 0 && value.st_uid != owner) ||
                   ((value.st_mode & 0022) && !(value.st_mode & S_ISVTX))
               ? EACCES
               : 0;
}

class Directory {
  public:
    int fd = -1;

    ~Directory() {
        if (fd >= 0)
            ::close(fd);
    }

    int open(const char* path, bool create) {
        size_t length = strnlen(path, 256);
        if (length < 2 || length >= 256 || path[0] != '/')
            return EINVAL;
        // Check the complete spelling before interpreting a missing component.
        for (size_t start = 1, end; start < length; start = end + 1) {
            end = start;
            while (end < length && path[end] != '/')
                end++;
            size_t size = end - start;
            if (!size || (size == 1 && path[start] == '.') ||
                (size == 2 && path[start] == '.' && path[start + 1] == '.'))
                return EINVAL;
        }
        fd = ::open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (fd < 0)
            return errno;
        int error = directory_policy(fd, false);
        for (size_t start = 1, end; !error && start < length; start = end + 1) {
            end = start;
            while (end < length && path[end] != '/')
                end++;
            char component[256];
            memcpy(component, path + start, end - start);
            component[end - start] = 0;
            bool created = false;
            if (create) {
                created = mkdirat(fd, component, 0700) == 0;
                if (!created && errno != EEXIST)
                    return errno;
                if (created) {
                    struct stat value;
                    if (fstatat(fd, component, &value, AT_SYMLINK_NOFOLLOW) < 0)
                        return errno;
                    if (!S_ISDIR(value.st_mode) || value.st_uid != geteuid())
                        return EACCES;
                    // The validated parent prevents an untrusted writer from
                    // replacing our new entry, including in a sticky parent.
                    // Restore access removed by umask before opening the child.
                    if (fchmodat(fd, component, 0700, 0) < 0)
                        return errno;
                }
            }
            int next = openat(fd, component, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
            if (next < 0)
                return errno;
            error = directory_policy(next, end == length);
            if (!error && created && (fsync(next) < 0 || fsync(fd) < 0))
                error = errno;
            error = finish(fd, error);
            fd = next;
        }
        return error;
    }

    int close(int error) {
        int current = fd;
        fd = -1;
        return current < 0 ? error : finish(current, error);
    }
};

int file_policy(const struct stat& value) {
    if (S_ISLNK(value.st_mode))
        return ELOOP;
    if (!S_ISREG(value.st_mode))
        return EINVAL;
    return value.st_uid == geteuid() && (value.st_mode & 07777) == 0600 && value.st_nlink == 1
               ? 0
               : EACCES;
}

int input(int directory, const char* name, int& fd) {
    struct stat before, after;
    if (fstatat(directory, name, &before, AT_SYMLINK_NOFOLLOW) < 0)
        return errno;
    int error = file_policy(before);
    if (error)
        return error;
    fd = openat(directory, name, O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0)
        return errno;
    if (fstat(fd, &after) < 0)
        error = errno;
    else if ((error = file_policy(after)) == 0 &&
             (before.st_dev != after.st_dev || before.st_ino != after.st_ino))
        error = ESTALE;
    if (error) {
        error = finish(fd, error);
        fd = -1;
    }
    return error;
}
} // namespace

int read(const char* directory, const char* name, char* output, size_t capacity, size_t& size) {
    Directory parent;
    int error = parent.open(directory, false), fd = -1;
    if (!error)
        error = input(parent.fd, name, fd);
    size_t used = 0;
    while (!error && used < capacity) {
        ssize_t count = ::read(fd, output + used, capacity - used);
        if (count < 0 && errno == EINTR)
            continue;
        if (count < 0)
            error = errno;
        else if (!count)
            break;
        else
            used += size_t(count);
    }
    if (!error && used == capacity)
        error = EFBIG;
    if (fd >= 0)
        error = finish(fd, error);
    error = parent.close(error);
    if (!error)
        size = used;
    return error;
}

int write(const char* directory, const char* name, const void* bytes, size_t size) {
    Directory parent;
    int error = parent.open(directory, true), previous = -1;
    if (error)
        return error;
    error = input(parent.fd, name, previous);
    if (error != 0 && error != ENOENT)
        return error;
    if (previous >= 0 && (error = finish(previous)) != 0)
        return error;
    error = 0;
    static unsigned serial = 0;
    char temporary[64];
    int fd = -1;
    for (unsigned attempt = 0; attempt < 8; attempt++) {
        int count =
            snprintf(temporary, sizeof(temporary), "%s.tmp.%ld.%u", name, long(getpid()), ++serial);
        if (count < 0 || size_t(count) >= sizeof(temporary))
            return ENAMETOOLONG;
        fd = openat(parent.fd, temporary, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                    0600);
        if (fd >= 0)
            break;
        if (errno != EEXIST)
            return errno;
    }
    if (fd < 0)
        return EEXIST;
    if (fchmod(fd, 0600) < 0)
        error = errno;
    size_t used = 0;
    while (!error && used < size) {
        ssize_t count = ::write(fd, static_cast<const char*>(bytes) + used, size - used);
        if (count < 0 && errno == EINTR)
            continue;
        if (count <= 0)
            error = count < 0 ? errno : EIO;
        else
            used += size_t(count);
    }
    if (!error && fsync(fd) < 0)
        error = errno;
    error = finish(fd, error);
    if (!error && renameat(parent.fd, temporary, parent.fd, name) < 0)
        error = errno;
    if (error) {
        if (unlinkat(parent.fd, temporary, 0) < 0)
            return errno;
    } else if (fsync(parent.fd) < 0)
        error = errno;
    return parent.close(error);
}

int remove(const char* directory, const char* name) {
    Directory parent;
    int error = parent.open(directory, false), fd = -1;
    if (!error)
        error = input(parent.fd, name, fd);
    if (error == ENOENT)
        return parent.close(0);
    if (fd >= 0)
        error = finish(fd, error);
    if (!error && unlinkat(parent.fd, name, 0) < 0)
        error = errno;
    if (!error && fsync(parent.fd) < 0)
        error = errno;
    return parent.close(error);
}

int lock(const char* directory, const char* name, int& descriptor) {
    if (!directory || !name)
        return EINVAL;
    size_t length = strnlen(name, 64);
    if (!length || length == 64 || strchr(name, '/') || strchr(name, '\\') || !strcmp(name, ".") ||
        !strcmp(name, ".."))
        return EINVAL;
    Directory parent;
    int error = parent.open(directory, true), fd = -1;
    if (error)
        return error;
    struct stat before, after, named;
    bool created = false;
    for (unsigned attempt = 0; attempt < 8; attempt++) {
        if (fstatat(parent.fd, name, &before, AT_SYMLINK_NOFOLLOW) == 0) {
            error = file_policy(before);
            if (error)
                break;
            fd = openat(parent.fd, name, O_RDWR | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
        } else if (errno == ENOENT) {
            fd = openat(parent.fd, name,
                        O_RDWR | O_CREAT | O_EXCL | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC, 0600);
            if (fd < 0 && errno == EEXIST)
                continue;
            created = fd >= 0;
        } else {
            error = errno;
            break;
        }
        if (fd < 0)
            error = errno;
        break;
    }
    if (!error && fd < 0)
        error = EAGAIN;
    if (!error && created && fchmod(fd, 0600) < 0)
        error = errno;
    if (!error && fstat(fd, &after) < 0)
        error = errno;
    if (!error)
        error = file_policy(after);
    if (!error && !created && (before.st_dev != after.st_dev || before.st_ino != after.st_ino))
        error = ESTALE;
    if (!error && flock(fd, LOCK_EX | LOCK_NB) < 0)
        error = errno;
    if (!error && created && (fsync(fd) < 0 || fsync(parent.fd) < 0))
        error = errno;
    if (!error && fstatat(parent.fd, name, &named, AT_SYMLINK_NOFOLLOW) < 0)
        error = errno;
    if (!error)
        error = file_policy(named);
    if (!error && (named.st_dev != after.st_dev || named.st_ino != after.st_ino))
        error = ESTALE;
    error = parent.close(error);
    if (error)
        return fd < 0 ? error : finish(fd, error);
    descriptor = fd;
    return 0;
}
} // namespace ax::net::saved
