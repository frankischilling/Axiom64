// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include "home.h"
#include "protected.h"
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/fsuid.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/xattr.h>
#include <unistd.h>

struct account_home {
    int directory, fd, attempted;
    char name[256], temporary[40];
    struct account_home_key key;
};

static const char attribute[] = "trusted.axiom64.home";

static int failed(int error) {
    errno = error;
    return -1;
}

int account_home_path_valid(const char* path) {
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
    return 0;
}

static int parent(const char* path, char name[256], int create) {
    if (account_home_path_valid(path) < 0)
        return -1;
    size_t length = strlen(path);
    int fd = open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0)
        return -1;
    int error = 0;
    for (size_t start = 1, end; !error && start < length; start = end + 1) {
        struct stat value;
        if (fstat(fd, &value) < 0)
            error = errno;
        else if (!S_ISDIR(value.st_mode) || value.st_uid || value.st_gid ||
                 ((value.st_mode & 0022) && !(value.st_mode & S_ISVTX)))
            error = EACCES;
        end = start;
        while (end < length && path[end] != '/')
            end++;
        memcpy(name, path + start, end - start);
        name[end - start] = 0;
        if (end == length) {
            if (!error && (value.st_mode & 0022))
                error = EACCES;
            break;
        }
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

static int entry(struct account_home* home, const char* name, const struct stat* expected) {
    struct stat value;
    if (fstatat(home->directory, name, &value, AT_SYMLINK_NOFOLLOW) < 0)
        return errno == ENOENT ? 0 : -1;
    return value.st_dev == expected->st_dev && value.st_ino == expected->st_ino ? 1 : 2;
}

static int key_valid(const struct account_home_key* key) {
    unsigned char value = 0;
    if (key)
        for (unsigned i = 0; i < sizeof(key->bytes); i++)
            value |= key->bytes[i];
    return value != 0;
}

int account_home_key_new(struct account_home_key* key) {
    if (!key)
        return failed(EINVAL);
    if (account_nonce(key->bytes) < 0)
        return -1;
    return key_valid(key) ? 0 : failed(EIO);
}

static void temporary_name(char output[40], const struct account_home_key* key) {
    char name[35];
    account_nonce_name(name, 'h', key->bytes);
    memcpy(output, ".home-", 6);
    memcpy(output + 6, name + 2, 33);
}

static int create(const char* path, uid_t uid, gid_t gid, const struct account_home_key* key,
                  struct account_home** output) {
    if (!output)
        return failed(EINVAL);
    *output = NULL;
    if (uid == (uid_t)-1 || gid == (gid_t)-1)
        return failed(EINVAL);
    if (geteuid() || getegid() || (uid_t)setfsuid(-1) || (gid_t)setfsgid(-1))
        return failed(EPERM);
    struct account_home* home = calloc(1, sizeof(*home));
    if (!home)
        return -1;
    home->fd = -1;
    home->directory = parent(path, home->name, 1);
    if (home->directory < 0) {
        int error = errno;
        free(home);
        return failed(error);
    }
    *output = home;
    struct stat value;
    int error = 0;
    if (fstatat(home->directory, home->name, &value, AT_SYMLINK_NOFOLLOW) == 0)
        error = EEXIST;
    else if (errno != ENOENT)
        error = errno;
    if (key)
        home->key = *key;
    if (!error && !key && account_home_key_new(&home->key) < 0)
        error = errno;
    if (!error) {
        temporary_name(home->temporary, &home->key);
        if (mkdirat(home->directory, home->temporary, 0700) < 0) {
            error = errno;
            home->attempted = error != EEXIST;
        } else {
            home->attempted = 1;
            home->fd = openat(home->directory, home->temporary,
                              O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
            if (home->fd < 0)
                error = errno;
        }
    }
    if (!error && fstat(home->fd, &value) < 0)
        error = errno;
    if (!error && (!S_ISDIR(value.st_mode) || value.st_uid || value.st_gid))
        error = EACCES;
    if (!error &&
        fsetxattr(home->fd, attribute, home->key.bytes, sizeof(home->key.bytes), XATTR_CREATE) < 0)
        error = errno;
    if (!error && (fchown(home->fd, uid, gid) < 0 || fchmod(home->fd, 0700) < 0 ||
                   fsync(home->fd) < 0 || fsync(home->directory) < 0))
        error = errno;
    if (!error) {
        int matched = entry(home, home->temporary, &value);
        if (matched != 1)
            error = matched < 0 ? errno : ESTALE;
    }
    if (!error && syscall(SYS_renameat2, home->directory, home->temporary, home->directory,
                          home->name, 1u) < 0)
        error = errno;
    if (!error) {
        int matched = entry(home, home->name, &value);
        if (matched != 1)
            error = matched < 0 ? errno : ESTALE;
        else if (fsync(home->directory) < 0)
            error = errno;
    }
    return error ? failed(error) : 0;
}

int account_home_create(const char* path, uid_t uid, gid_t gid, struct account_home** output) {
    return create(path, uid, gid, NULL, output);
}

int account_home_create_key(const char* path, uid_t uid, gid_t gid,
                            const struct account_home_key* key, struct account_home** output) {
    if (!key_valid(key)) {
        if (output)
            *output = NULL;
        return failed(EINVAL);
    }
    return create(path, uid, gid, key, output);
}

int account_home_finish(struct account_home* home, int published) {
    if (!home)
        return 0;
    int error = 0;
    struct stat value;
    if (home->fd < 0) {
        if (home->attempted) {
            if (fstatat(home->directory, home->temporary, &value, AT_SYMLINK_NOFOLLOW) == 0)
                error = EIO;
            else if (errno != ENOENT)
                error = errno;
        }
    } else if (fstat(home->fd, &value) < 0)
        error = errno;
    else if (published) {
        int matched = entry(home, home->name, &value);
        if (matched != 1)
            error = matched < 0 ? errno : ESTALE;
    } else {
        int removed = 0;
        const char* names[] = {home->temporary, home->name};
        for (unsigned i = 0; i < 2; i++) {
            int matched = entry(home, names[i], &value);
            if (matched < 0 && !error)
                error = errno;
            if (matched != 1)
                continue;
            if (unlinkat(home->directory, names[i], AT_REMOVEDIR) < 0) {
                if (!error)
                    error = errno;
            } else
                removed = 1;
        }
        if (!removed && value.st_nlink && !error)
            error = ESTALE;
        if (home->attempted && fsync(home->directory) < 0 && !error)
            error = errno;
    }
    if (home->fd >= 0 && close(home->fd) < 0 && !error)
        error = errno;
    if (close(home->directory) < 0 && !error)
        error = errno;
    free(home);
    return error ? failed(error) : 0;
}

static int recover_entry(struct account_home* home, const char* name, int published) {
    int fd = openat(home->directory, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0)
        return errno == ENOENT && !published        ? 0
               : errno == ELOOP || errno == ENOTDIR ? failed(ESTALE)
                                                    : -1;
    struct account_home_key actual;
    ssize_t length = fgetxattr(fd, attribute, actual.bytes, sizeof(actual.bytes));
    int error = length < 0 ? errno : 0;
    if (length >= 0 &&
        ((size_t)length != sizeof(actual.bytes) || memcmp(&actual, &home->key, sizeof(actual))))
        error = ESTALE;
    if (error == ENODATA || error == ERANGE)
        error = ESTALE;
    struct stat value;
    if (!error && fstat(fd, &value) < 0)
        error = errno;
    if (!error) {
        int matched = entry(home, name, &value);
        if (matched != 1)
            error = matched < 0 ? errno : ESTALE;
    }
    if (!error && !published && unlinkat(home->directory, name, AT_REMOVEDIR) < 0)
        error = errno;
    if (close(fd) < 0 && !error)
        error = errno;
    return error ? failed(error) : 0;
}

int account_home_recover(const char* path, const struct account_home_key* key, int published) {
    if (!key_valid(key) || (published != 0 && published != 1))
        return failed(EINVAL);
    if (geteuid() || getegid() || (uid_t)setfsuid(-1) || (gid_t)setfsgid(-1))
        return failed(EPERM);
    struct account_home home = {.fd = -1, .key = *key};
    home.directory = parent(path, home.name, 0);
    if (home.directory < 0)
        return errno == ENOENT && !published ? 0 : -1;
    temporary_name(home.temporary, key);
    int error = 0;
    if (published) {
        if (recover_entry(&home, home.name, 1) < 0)
            error = errno;
    } else {
        if (recover_entry(&home, home.temporary, 0) < 0)
            error = errno;
        if (recover_entry(&home, home.name, 0) < 0 && !error)
            error = errno;
        if (fsync(home.directory) < 0 && !error)
            error = errno;
    }
    if (close(home.directory) < 0 && !error)
        error = errno;
    return error ? failed(error) : 0;
}
