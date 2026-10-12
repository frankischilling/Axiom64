// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
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

enum { seed_size = 32, private_open = O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC };

static void erase(void* data, size_t size) {
    volatile unsigned char* bytes = data;
    while (size--)
        *bytes++ = 0;
}

static int metadata(int fd, struct stat* status, unsigned links, int size) {
    if (fstat(fd, status) < 0)
        return -1;
    if (!S_ISREG(status->st_mode) || (status->st_mode & 07777) != 0600 || status->st_uid != 0 ||
        status->st_gid != 0 || status->st_nlink < 1 || status->st_nlink > links) {
        errno = EPERM;
        return -1;
    }
    if (size >= 0 && status->st_size != size) {
        errno = EINVAL;
        return -1;
    }
    return 0;
}

static int open_seed(int directory, const char* name, struct stat* status, unsigned links) {
    int fd = openat(directory, name, O_RDONLY | private_open);
    if (fd < 0)
        return -1;
    if (metadata(fd, status, links, seed_size) < 0) {
        int error = errno;
        close(fd);
        errno = error;
        return -1;
    }
    return fd;
}

static int safe_directory(const char* path) {
    if (path[0] != '/' || !path[1] || strlen(path) >= 1024) {
        errno = EINVAL;
        return -1;
    }
    char copy[1024];
    strcpy(copy, path + 1);
    for (char* part = copy;;) {
        char* separator = strchr(part, '/');
        size_t length = separator ? (size_t)(separator - part) : strlen(part);
        if (!length || length > 255 || (length == 1 && part[0] == '.') ||
            (length == 2 && part[0] == '.' && part[1] == '.')) {
            errno = EINVAL;
            return -1;
        }
        if (!separator)
            break;
        part = separator + 1;
    }
    int directory = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (directory < 0)
        return -1;
    struct stat anchor;
    if (fstat(directory, &anchor) < 0) {
        int error = errno;
        close(directory);
        errno = error;
        return -1;
    }
    if (anchor.st_uid != 0 || anchor.st_gid != 0 || !S_ISDIR(anchor.st_mode) ||
        (anchor.st_mode & 0022)) {
        close(directory);
        errno = EPERM;
        return -1;
    }
    char* component = copy;
    for (;;) {
        char* next = strchr(component, '/');
        if (next)
            *next = 0;
        if (!*component || !strcmp(component, ".") || !strcmp(component, "..")) {
            errno = EINVAL;
            break;
        }
        int child = openat(directory, component, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (child < 0 && errno == ENOENT) {
            if (mkdirat(directory, component, 0700) < 0 && errno != EEXIST)
                break;
            if (fsync(directory) < 0)
                break;
            child = openat(directory, component, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        }
        if (child < 0)
            break;
        struct stat status;
        if (fstat(child, &status) < 0) {
            int error = errno;
            close(child);
            errno = error;
            break;
        }
        if (!S_ISDIR(status.st_mode) || status.st_uid != 0 || status.st_gid != 0 ||
            (status.st_mode & 0022) || (!next && (status.st_mode & 07777) != 0700)) {
            close(child);
            errno = EPERM;
            break;
        }
        close(directory);
        directory = child;
        if (!next)
            return directory;
        component = next + 1;
    }
    int error = errno;
    close(directory);
    errno = error;
    return -1;
}

static int singleton(int directory) {
    int fd = openat(directory, "lock", O_RDONLY | private_open);
    if (fd < 0 && errno == ENOENT) {
        fd = openat(directory, "lock", O_RDWR | O_CREAT | O_EXCL | private_open, 0600);
        if (fd < 0)
            return -1;
        if (fsync(fd) < 0 || fsync(directory) < 0) {
            int error = errno;
            close(fd);
            errno = error;
            return -1;
        }
    }
    if (fd < 0)
        return -1;
    struct stat status;
    if (metadata(fd, &status, 1, 0) < 0 || flock(fd, LOCK_EX | LOCK_NB) < 0) {
        int error = errno;
        close(fd);
        errno = error;
        return -1;
    }
    return fd;
}

static int recover_previous(int directory) {
    struct stat previous, current;
    int backup = open_seed(directory, "seed.previous", &previous, 2);
    if (backup < 0)
        return errno == ENOENT ? 0 : -1;
    close(backup);
    int fd = open_seed(directory, "seed", &current, 2);
    if (fd < 0) {
        if (errno != ENOENT)
            return -1;
        if (previous.st_nlink != 1) {
            errno = EPERM;
            return -1;
        }
        if (renameat(directory, "seed.previous", directory, "seed") < 0 || fsync(directory) < 0)
            return -1;
        puts("RANDOM_SEED_RECOVERED state=previous-restored");
        return 0;
    }
    close(fd);
    int same = previous.st_dev == current.st_dev && previous.st_ino == current.st_ino;
    if ((same && (previous.st_nlink != 2 || current.st_nlink != 2)) ||
        (!same && (previous.st_nlink != 1 || current.st_nlink != 1))) {
        errno = EPERM;
        return -1;
    }
    if (unlinkat(directory, "seed.previous", 0) < 0 || fsync(directory) < 0)
        return -1;
    puts("RANDOM_SEED_RECOVERED state=complete-seed-retained");
    return 0;
}

static int temporary_name(const char* name) {
    if (strncmp(name, "seed.tmp.", 9))
        return 0;
    const char* part = name + 9;
    for (unsigned field = 0; field < 2; field++) {
        unsigned digits = 0;
        while (*part >= '0' && *part <= '9') {
            part++;
            digits++;
        }
        if (!digits || digits > 10 || (field == 0 ? *part++ != '.' : *part != 0))
            return 0;
    }
    return 1;
}

static int recover_temporaries(int directory) {
    int fd = openat(directory, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0)
        return -1;
    DIR* stream = fdopendir(fd);
    if (!stream) {
        int error = errno;
        close(fd);
        errno = error;
        return -1;
    }
    char names[256][64];
    unsigned count = 0;
    errno = 0;
    struct dirent* entry;
    while ((entry = readdir(stream))) {
        if (!temporary_name(entry->d_name))
            continue;
        if (count == 256 || strlen(entry->d_name) >= sizeof(names[0])) {
            closedir(stream);
            errno = EOVERFLOW;
            return -1;
        }
        strcpy(names[count++], entry->d_name);
    }
    int error = errno;
    closedir(stream);
    if (error) {
        errno = error;
        return -1;
    }
    for (unsigned i = 0; i < count; i++) {
        int temporary = openat(directory, names[i], O_RDONLY | private_open);
        struct stat status;
        if (temporary < 0)
            return -1;
        int valid = metadata(temporary, &status, 1, -1);
        error = errno;
        close(temporary);
        if (valid < 0 || status.st_size < 0 || status.st_size > seed_size) {
            errno = valid < 0 ? error : EINVAL;
            return -1;
        }
    }
    for (unsigned i = 0; i < count; i++)
        if (unlinkat(directory, names[i], 0) < 0)
            return -1;
    if (count && fsync(directory) < 0)
        return -1;
    printf("RANDOM_SEED_RECOVERED temporary_files=%u\n", count);
    return 0;
}

static int write_all(int fd, const void* data, size_t size) {
    const unsigned char* bytes = data;
    size_t written = 0;
    while (written < size) {
        ssize_t result = write(fd, bytes + written, size - written);
        if (result < 0 && errno == EINTR)
            continue;
        if (result <= 0) {
            if (!result)
                errno = EIO;
            return -1;
        }
        written += result;
    }
    return 0;
}

static int load(int directory, int* present) {
    struct stat before, after;
    int fd = open_seed(directory, "seed", &before, 1);
    if (fd < 0) {
        if (errno != ENOENT)
            return -1;
        *present = 0;
        puts("RANDOM_SEED_LOADED state=absent credited_bits=0");
        return 0;
    }
    *present = 1;
    unsigned char seed[seed_size];
    size_t read_count = 0;
    int result = -1;
    while (read_count < sizeof(seed)) {
        ssize_t count = read(fd, seed + read_count, sizeof(seed) - read_count);
        if (count < 0 && errno == EINTR)
            continue;
        if (count <= 0) {
            if (!count)
                errno = EIO;
            goto finished;
        }
        read_count += count;
    }
    if (metadata(fd, &after, 1, seed_size) < 0)
        goto finished;
    if (before.st_ino != after.st_ino || before.st_dev != after.st_dev) {
        errno = EPERM;
        goto finished;
    }
    int random_fd = open("/dev/urandom", O_WRONLY | O_CLOEXEC);
    if (random_fd < 0)
        goto finished;
    result = write_all(random_fd, seed, sizeof(seed));
    int error = errno;
    if (close(random_fd) < 0 && result == 0) {
        error = errno;
        result = -1;
    }
    errno = error;
finished:
    error = errno;
    erase(seed, sizeof(seed));
    if (close(fd) < 0 && result == 0) {
        error = errno;
        result = -1;
    }
    errno = error;
    if (result == 0)
        puts("RANDOM_SEED_LOADED bytes=32 credited_bits=0");
    return result;
}

static int rotate(int directory, int present, int nonblock, const char** stage) {
    unsigned char seed[seed_size];
    size_t generated = 0;
    char name[64] = {0};
    int fd = -1, temporary = 0, backup = 0, publication_attempted = 0, committed = 0, result = -1;
    *stage = "initialized-output";
    while (generated < sizeof(seed)) {
        ssize_t count =
            getrandom(seed + generated, sizeof(seed) - generated, nonblock ? GRND_NONBLOCK : 0);
        if (count < 0 && errno == EINTR)
            continue;
        if (count <= 0) {
            if (!count)
                errno = EIO;
            goto finished;
        }
        generated += count;
    }
    *stage = "private-temporary";
    for (unsigned attempt = 0; attempt < 64; attempt++) {
        snprintf(name, sizeof(name), "seed.tmp.%ld.%u", (long)getpid(), attempt);
        fd = openat(directory, name, O_RDWR | O_CREAT | O_EXCL | private_open, 0600);
        if (fd >= 0 || errno != EEXIST)
            break;
    }
    if (fd < 0)
        goto finished;
    temporary = 1;
    struct stat status;
    if (metadata(fd, &status, 1, 0) < 0)
        goto finished;
    *stage = "temporary-write-and-sync";
    if (write_all(fd, seed, sizeof(seed)) < 0 || fsync(fd) < 0 ||
        metadata(fd, &status, 1, seed_size) < 0)
        goto finished;
    int closed = close(fd);
    fd = -1;
    if (closed < 0)
        goto finished;
    *stage = "previous-seed-checkpoint";
    if (present) {
        int old = open_seed(directory, "seed", &status, 1);
        if (old < 0)
            goto finished;
        close(old);
        if (linkat(directory, "seed", directory, "seed.previous", 0) < 0)
            goto finished;
        backup = 1;
        if (fsync(directory) < 0)
            goto finished;
    }
    *stage = "atomic-publication";
    // EIO can follow a visible namespace change. Roll back every attempted
    // publication, including a rename that reports failure after taking effect.
    publication_attempted = 1;
    if (renameat(directory, name, directory, "seed") < 0)
        goto finished;
    temporary = 0;
    *stage = "directory-commit";
    if (fsync(directory) < 0)
        goto finished;
    committed = 1;
    // A durable replacement is complete. A leftover previous file is safe to recover next boot.
    int cleanup_pending = 0;
    if (backup && (unlinkat(directory, "seed.previous", 0) < 0 || fsync(directory) < 0))
        cleanup_pending = 1;
    printf("RANDOM_SEED_ROTATED bytes=32 previous=%d cleanup_pending=%d\n", present,
           cleanup_pending);
    result = 0;
finished: {
    int error = errno;
    erase(seed, sizeof(seed));
    if (fd >= 0)
        close(fd);
    if (!committed) {
        if (backup && publication_attempted) {
            if (renameat(directory, "seed.previous", directory, "seed") == 0) {
                // Renaming two links to the same inode can be a successful no-op.
                (void)unlinkat(directory, "seed.previous", 0);
                (void)fsync(directory);
            }
        } else if (backup) {
            if (unlinkat(directory, "seed.previous", 0) == 0)
                (void)fsync(directory);
        } else if (publication_attempted) {
            if (unlinkat(directory, "seed", 0) == 0)
                (void)fsync(directory);
        }
        if (temporary && unlinkat(directory, name, 0) == 0)
            (void)fsync(directory);
    }
    errno = error;
    return result;
}
}

int main(int argc, char** argv) {
    const char* directory_name = "/var/lib/axiom64/random";
    int nonblock = 0;
    if (argc < 2 ||
        (strcmp(argv[1], "boot") && strcmp(argv[1], "load") && strcmp(argv[1], "rotate"))) {
        fprintf(stderr, "usage: random-seed boot|load|rotate [--nonblock] [--directory PATH]\n");
        return 2;
    }
    for (int i = 2; i < argc; i++) {
        if (!strcmp(argv[i], "--nonblock"))
            nonblock = 1;
        else if (!strcmp(argv[i], "--directory") && i + 1 < argc)
            directory_name = argv[++i];
        else
            return 2;
    }
    setbuf(stdout, NULL);
    umask(077);
    const char* stage = "root-identity";
    int directory = -1, lock = -1, present = 0, result = 1;
    if (geteuid() != 0 || getegid() != 0) {
        errno = EPERM;
        goto finished;
    }
    stage = "private-directory";
    directory = safe_directory(directory_name);
    if (directory < 0)
        goto finished;
    stage = "singleton-ownership";
    lock = singleton(directory);
    if (lock < 0)
        goto finished;
    stage = "previous-generation-recovery";
    if (recover_previous(directory) < 0)
        goto finished;
    stage = "temporary-recovery";
    if (recover_temporaries(directory) < 0)
        goto finished;
    stage = "uncredited-loading";
    if (load(directory, &present) < 0)
        goto finished;
    if (strcmp(argv[1], "load") && rotate(directory, present, nonblock, &stage) < 0)
        goto finished;
    result = 0;
finished: {
    int error = errno;
    if (lock >= 0 && close(lock) < 0 && result == 0) {
        result = 1;
        error = errno;
        stage = "lock-close";
    }
    if (directory >= 0 && close(directory) < 0 && result == 0) {
        result = 1;
        error = errno;
        stage = "directory-close";
    }
    if (result)
        fprintf(stderr, "RANDOM_SEED_FAILED stage=%s error=%d\n", stage, error);
    else
        printf("RANDOM_SEED_PASS mode=%s loaded=%d credited_bits=0\n", argv[1], present);
    return result;
}
}
