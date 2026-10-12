// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include "store.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <unistd.h>

static const char* names[ACCOUNT_FILE_COUNT] = {"passwd", "group", "shadow"};

struct account_store {
    int directory, lock, initialized, attempted;
    char current[35];
    struct account_content files[ACCOUNT_FILE_COUNT];
};

static int failed(int error) {
    errno = error;
    return -1;
}

static int directory_policy(int fd, int final) {
    struct stat value;
    if (fstat(fd, &value) < 0)
        return -1;
    if (!S_ISDIR(value.st_mode))
        return failed(ENOTDIR);
    if (value.st_uid || value.st_gid ||
        (final ? (value.st_mode & 07777) != 0755
               : ((value.st_mode & 0022) && !(value.st_mode & S_ISVTX))))
        return failed(EACCES);
    return 0;
}

static int directory_open(const char* path, int provision) {
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
    int error = directory_policy(fd, 0) < 0 ? errno : 0;
    for (size_t start = 1, end; !error && start < length; start = end + 1) {
        end = start;
        while (end < length && path[end] != '/')
            end++;
        char component[256];
        memcpy(component, path + start, end - start);
        component[end - start] = 0;
        int created = 0;
        if (provision) {
            created = mkdirat(fd, component, 0755) == 0;
            if (!created && errno != EEXIST)
                error = errno;
            if (created) {
                struct stat value;
                if (fstatat(fd, component, &value, AT_SYMLINK_NOFOLLOW) < 0)
                    error = errno;
                else if (!S_ISDIR(value.st_mode) || value.st_uid || value.st_gid)
                    error = EACCES;
                else if (fchmodat(fd, component, 0755, 0) < 0)
                    error = errno;
            }
        }
        int next =
            error ? -1 : openat(fd, component, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (next < 0 && !error)
            error = errno;
        if (!error && directory_policy(next, end == length) < 0)
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

static int generation_name(const char* name) {
    if (strlen(name) != 34 || name[0] != 'g' || name[1] != '-')
        return 0;
    for (unsigned i = 2; i < 34; i++)
        if (!((name[i] >= '0' && name[i] <= '9') || (name[i] >= 'a' && name[i] <= 'f')))
            return 0;
    return 1;
}

static int load_file(int directory, unsigned kind, struct account_content* output) {
    int fd = openat(directory, names[kind], O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0)
        return -1;
    int error = regular_policy(fd, kind == ACCOUNT_SHADOW ? 0600 : 0644) < 0 ? errno : 0;
    struct stat value;
    size_t size = 0;
    char* data = NULL;
    if (!error && fstat(fd, &value) < 0)
        error = errno;
    if (!error && (value.st_size <= 0 || value.st_size > ACCOUNT_FILE_LIMIT))
        error = EFBIG;
    if (!error) {
        size = (size_t)value.st_size;
        data = malloc(size + 1);
        if (!data)
            error = ENOMEM;
    }
    for (size_t offset = 0; !error && offset < size;) {
        ssize_t count = read(fd, data + offset, size - offset);
        if (count < 0 && errno == EINTR)
            continue;
        if (count <= 0)
            error = count < 0 ? errno : EIO;
        else
            offset += (size_t)count;
    }
    if (!error && (data[size - 1] != '\n' || memchr(data, 0, size)))
        error = EINVAL;
    if (close(fd) < 0 && !error)
        error = errno;
    if (error) {
        if (data) {
            explicit_bzero(data, size + 1);
            free(data);
        }
        return failed(error);
    }
    data[size] = 0;
    *output = (struct account_content){data, size};
    return 0;
}

static int fresh_store(int directory) {
    int duplicate = dup(directory);
    if (duplicate < 0)
        return -1;
    DIR* stream = fdopendir(duplicate);
    if (!stream) {
        int error = errno;
        close(duplicate);
        return failed(error);
    }
    int error = 0;
    for (;;) {
        errno = 0;
        struct dirent* entry = readdir(stream);
        if (!entry) {
            error = errno;
            break;
        }
        if (strcmp(entry->d_name, ".") && strcmp(entry->d_name, "..") &&
            strcmp(entry->d_name, "lock")) {
            error = EUCLEAN;
            break;
        }
    }
    if (closedir(stream) < 0 && !error)
        error = errno;
    return error ? failed(error) : 0;
}

void account_store_end(struct account_store* store) {
    if (!store)
        return;
    for (unsigned i = 0; i < ACCOUNT_FILE_COUNT; i++)
        if (store->files[i].data) {
            explicit_bzero((void*)store->files[i].data, store->files[i].size + 1);
            free((void*)store->files[i].data);
        }
    if (store->lock >= 0)
        close(store->lock);
    if (store->directory >= 0)
        close(store->directory);
    explicit_bzero(store, sizeof(*store));
    free(store);
}

int account_store_begin(const char* path, int provision, struct account_store** output) {
    if (!output || (provision != 0 && provision != 1))
        return failed(EINVAL);
    *output = NULL;
    if (geteuid() || getegid())
        return failed(EPERM);
    struct account_store* store = calloc(1, sizeof(*store));
    if (!store)
        return -1;
    store->directory = directory_open(path, provision);
    store->lock = -1;
    int error = store->directory < 0 ? errno : 0;
    if (!error) {
        store->lock = openat(store->directory, "lock",
                             O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
        int created = store->lock >= 0;
        if (!created && errno == EEXIST)
            store->lock = openat(store->directory, "lock", O_RDWR | O_NOFOLLOW | O_CLOEXEC);
        if (store->lock < 0)
            error = errno;
        else if (created && fchmod(store->lock, 0600) < 0)
            error = errno;
        else if (regular_policy(store->lock, 0600) < 0)
            error = errno;
        if (!error && created && (fsync(store->lock) < 0 || fsync(store->directory) < 0))
            error = errno;
    }
    while (!error && flock(store->lock, LOCK_EX) < 0)
        if (errno != EINTR)
            error = errno;
    struct stat link;
    int directory = -1;
    if (!error && fstatat(store->directory, "current", &link, AT_SYMLINK_NOFOLLOW) < 0) {
        if (errno != ENOENT || !provision)
            error = errno;
        else if (fresh_store(store->directory) < 0)
            error = errno;
    } else if (!error) {
        if (!S_ISLNK(link.st_mode) || link.st_uid || link.st_gid || link.st_nlink != 1)
            error = EACCES;
        ssize_t length = error ? -1 : readlinkat(store->directory, "current", store->current, 35);
        if (length < 0 && !error)
            error = errno;
        if (!error && length != 34)
            error = EINVAL;
        if (!error) {
            store->current[34] = 0;
            if (!generation_name(store->current))
                error = EINVAL;
        }
        if (!error) {
            directory = openat(store->directory, store->current,
                               O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
            if (directory < 0)
                error = errno;
            else if (directory_policy(directory, 1) < 0)
                error = errno;
        }
        for (unsigned i = 0; !error && i < ACCOUNT_FILE_COUNT; i++)
            if (load_file(directory, i, &store->files[i]) < 0)
                error = errno;
        store->initialized = !error;
    }
    if (directory >= 0 && close(directory) < 0 && !error)
        error = errno;
    if (error) {
        account_store_end(store);
        return failed(error);
    }
    *output = store;
    return 0;
}

const struct account_content* account_store_snapshot(const struct account_store* store) {
    return store && store->initialized ? store->files : NULL;
}

const char* account_store_revision(const struct account_store* store) {
    return store && store->initialized ? store->current : NULL;
}

static int random_name(char output[35]) {
    unsigned char bytes[16];
    for (size_t offset = 0; offset < sizeof(bytes);) {
        ssize_t count = getrandom(bytes + offset, sizeof(bytes) - offset, 0);
        if (count < 0 && errno == EINTR)
            continue;
        if (count <= 0) {
            int error = count < 0 ? errno : EIO;
            explicit_bzero(bytes, sizeof(bytes));
            return failed(error);
        }
        offset += (size_t)count;
    }
    memcpy(output, "g-", 2);
    for (unsigned i = 0; i < sizeof(bytes); i++) {
        output[2 + i * 2] = "0123456789abcdef"[bytes[i] >> 4];
        output[3 + i * 2] = "0123456789abcdef"[bytes[i] & 15];
    }
    output[34] = 0;
    explicit_bzero(bytes, sizeof(bytes));
    return 0;
}

static int write_file(int directory, unsigned kind, struct account_content content) {
    int fd =
        openat(directory, names[kind], O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0)
        return -1;
    int error = 0;
    for (size_t offset = 0; !error && offset < content.size;) {
        ssize_t count = write(fd, content.data + offset, content.size - offset);
        if (count < 0 && errno == EINTR)
            continue;
        if (count <= 0)
            error = count < 0 ? errno : EIO;
        else
            offset += (size_t)count;
    }
    if (!error && (fchmod(fd, kind == ACCOUNT_SHADOW ? 0600 : 0644) < 0 || fsync(fd) < 0))
        error = errno;
    if (close(fd) < 0 && !error)
        error = errno;
    return error ? failed(error) : 0;
}

static int remove_generation(int parent, const char* name) {
    int fd = openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0)
        return -1;
    struct stat value;
    int error = fstat(fd, &value) < 0 ? errno : 0;
    if (!error && (value.st_uid || value.st_gid ||
                   ((value.st_mode & 07777) != 0700 && (value.st_mode & 07777) != 0755)))
        error = EACCES;
    int scan = error ? -1 : openat(fd, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (scan < 0 && !error)
        error = errno;
    DIR* entries = scan < 0 ? NULL : fdopendir(scan);
    if (!entries && scan >= 0) {
        error = errno;
        close(scan);
    }
    while (!error && entries) {
        errno = 0;
        struct dirent* entry = readdir(entries);
        if (!entry) {
            error = errno;
            break;
        }
        if (strcmp(entry->d_name, ".") && strcmp(entry->d_name, "..") &&
            strcmp(entry->d_name, "passwd") && strcmp(entry->d_name, "group") &&
            strcmp(entry->d_name, "shadow"))
            error = ENOTEMPTY;
    }
    if (entries && closedir(entries) < 0 && !error)
        error = errno;
    for (unsigned i = 0; !error && i < ACCOUNT_FILE_COUNT; i++) {
        if (fstatat(fd, names[i], &value, AT_SYMLINK_NOFOLLOW) < 0) {
            if (errno != ENOENT)
                error = errno;
        } else if (!S_ISREG(value.st_mode) || value.st_uid || value.st_gid || value.st_nlink != 1 ||
                   ((value.st_mode & 07777) != 0600 &&
                    (i == ACCOUNT_SHADOW || (value.st_mode & 07777) != 0644)))
            error = EACCES;
    }
    for (unsigned i = 0; !error && i < ACCOUNT_FILE_COUNT; i++)
        if (unlinkat(fd, names[i], 0) < 0 && errno != ENOENT)
            error = errno;
    if (!error && fsync(fd) < 0)
        error = errno;
    if (close(fd) < 0 && !error)
        error = errno;
    if (!error && unlinkat(parent, name, AT_REMOVEDIR) < 0)
        error = errno;
    return error ? failed(error) : 0;
}

static int collect(struct account_store* store, const char* current) {
    int fd = openat(store->directory, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0)
        return -1;
    DIR* entries = fdopendir(fd);
    if (!entries) {
        int error = errno;
        close(fd);
        return failed(error);
    }
    int error = 0;
    while (!error) {
        errno = 0;
        struct dirent* entry = readdir(entries);
        if (!entry) {
            error = errno;
            break;
        }
        if (generation_name(entry->d_name) && strcmp(entry->d_name, current) &&
            strcmp(entry->d_name, store->current) &&
            remove_generation(store->directory, entry->d_name) < 0)
            error = errno;
        // An interrupted pointer publication may leave an unused root-owned
        // link. Check its exact spelling and target before removing it.
        if (entry->d_name[0] == 'p' && strlen(entry->d_name) == 34) {
            char expected[35], target[35];
            memcpy(expected, entry->d_name, 35);
            expected[0] = 'g';
            if (!generation_name(expected))
                continue;
            struct stat value;
            if (fstatat(store->directory, entry->d_name, &value, AT_SYMLINK_NOFOLLOW) < 0)
                error = errno;
            else if (!S_ISLNK(value.st_mode) || value.st_uid || value.st_gid || value.st_nlink != 1)
                error = EACCES;
            ssize_t length =
                error ? -1 : readlinkat(store->directory, entry->d_name, target, sizeof(target));
            if (length < 0 && !error)
                error = errno;
            if (!error && (length != 34 || memcmp(target, expected, 34)))
                error = EUCLEAN;
            if (!error && unlinkat(store->directory, entry->d_name, 0) < 0)
                error = errno;
        }
    }
    if (closedir(entries) < 0 && !error)
        error = errno;
    if (!error && fsync(store->directory) < 0)
        error = errno;
    return error ? failed(error) : 0;
}

int account_store_commit(struct account_store* store,
                         const struct account_content files[ACCOUNT_FILE_COUNT], int* published) {
    if (!store || !files || !published)
        return failed(EINVAL);
    *published = 0;
    if (store->attempted)
        return failed(EALREADY);
    store->attempted = 1;
    for (unsigned i = 0; i < ACCOUNT_FILE_COUNT; i++)
        if (!files[i].data || !files[i].size || files[i].size > ACCOUNT_FILE_LIMIT ||
            files[i].data[files[i].size - 1] != '\n' || memchr(files[i].data, 0, files[i].size))
            return failed(EINVAL);
    char generation[35], pointer[35];
    int directory = -1, created = 0, pointer_created = 0, error = 0;
    for (unsigned attempt = 0; !created && attempt < 8; attempt++) {
        if (random_name(generation) < 0)
            return -1;
        created = mkdirat(store->directory, generation, 0700) == 0;
        if (!created && errno != EEXIST)
            return -1;
    }
    if (!created)
        return failed(EEXIST);
    // The parent is root-owned and not writable by another user. Restore access
    // removed by umask before opening this new, exclusively created directory.
    if (fchmodat(store->directory, generation, 0700, 0) < 0)
        error = errno;
    if (!error) {
        directory =
            openat(store->directory, generation, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (directory < 0)
            error = errno;
    }
    for (unsigned i = 0; !error && i < ACCOUNT_FILE_COUNT; i++)
        if (write_file(directory, i, files[i]) < 0)
            error = errno;
    if (!error &&
        (fchmod(directory, 0755) < 0 || fsync(directory) < 0 || fsync(store->directory) < 0))
        error = errno;
    memcpy(pointer, generation, sizeof(pointer));
    pointer[0] = 'p';
    if (!error) {
        pointer_created = symlinkat(generation, store->directory, pointer) == 0;
        if (!pointer_created)
            error = errno;
    }
    if (!error && fsync(store->directory) < 0)
        error = errno;
    if (!error && renameat(store->directory, pointer, store->directory, "current") < 0)
        error = errno;
    else if (!error) {
        *published = 1;
        pointer_created = 0;
        if (fsync(store->directory) < 0)
            error = errno;
    }
    if (pointer_created)
        unlinkat(store->directory, pointer, 0);
    if (!*published) {
        if (directory >= 0)
            for (unsigned i = 0; i < ACCOUNT_FILE_COUNT; i++)
                unlinkat(directory, names[i], 0);
        unlinkat(store->directory, generation, AT_REMOVEDIR);
    }
    if (directory >= 0 && close(directory) < 0 && !error)
        error = errno;
    if (*published && !error && collect(store, generation) < 0)
        error = errno;
    return error ? failed(error) : 0;
}
