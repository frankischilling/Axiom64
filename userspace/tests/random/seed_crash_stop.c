// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int __real_openat(int, const char*, int, ...);
ssize_t __real_write(int, const void*, size_t);
int __real_fsync(int);
int __real_linkat(int, const char*, int, const char*, int);
int __real_renameat(int, const char*, int, const char*);
int __real_unlinkat(int, const char*, int);

static int temporary_fd = -1;
static int checkpoint, published;

// This fixture preserves the real calls and stops only between them. The
// installed service has no wrappers, environment controls or crash markers.
static void boundary(const char* point) {
    const char* selected = getenv("AXIOM64_SEED_CRASH_POINT");
    if (selected && !strcmp(selected, point)) {
        printf("RANDOM_SEED_CRASH_STOP point=%s\n", point);
        fflush(stdout);
        if (raise(SIGSTOP) < 0)
            _exit(125);
    }
}

int __wrap_openat(int directory, const char* name, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list arguments;
        va_start(arguments, flags);
        mode = va_arg(arguments, int);
        va_end(arguments);
    }
    int fd = __real_openat(directory, name, flags, mode);
    if (fd >= 0 && (flags & O_CREAT) && !strncmp(name, "seed.tmp.", 9)) {
        temporary_fd = fd;
        boundary("temporary-created");
    }
    return fd;
}

ssize_t __wrap_write(int fd, const void* data, size_t size) {
    ssize_t result = __real_write(fd, data, size);
    if (fd == temporary_fd && result > 0)
        boundary("temporary-written");
    return result;
}

int __wrap_fsync(int fd) {
    int result = __real_fsync(fd);
    if (result == 0) {
        if (fd == temporary_fd)
            boundary("temporary-synced");
        else if (published)
            boundary("committed");
        else if (checkpoint)
            boundary("checkpoint-synced");
    }
    return result;
}

int __wrap_linkat(int old_directory, const char* old_name, int new_directory, const char* new_name,
                  int flags) {
    int result = __real_linkat(old_directory, old_name, new_directory, new_name, flags);
    if (result == 0 && !strcmp(new_name, "seed.previous"))
        checkpoint = 1;
    return result;
}

int __wrap_renameat(int old_directory, const char* old_name, int new_directory,
                    const char* new_name) {
    int publication = !strncmp(old_name, "seed.tmp.", 9) && !strcmp(new_name, "seed");
    if (publication)
        boundary("before-publication");
    int result = __real_renameat(old_directory, old_name, new_directory, new_name);
    if (publication && result == 0) {
        published = 1;
        boundary("published");
    }
    return result;
}

int __wrap_unlinkat(int directory, const char* name, int flags) {
    int result = __real_unlinkat(directory, name, flags);
    if (result == 0 && published && !strcmp(name, "seed.previous"))
        boundary("cleanup-unlinked");
    return result;
}
