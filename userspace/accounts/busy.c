// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include "busy.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/statfs.h>
#include <unistd.h>

static int failed(int error) {
    errno = error;
    return -1;
}

static int numeric_pid(const char* name) {
    if (!*name || *name == '0')
        return 0;
    uint32_t value = 0;
    for (; *name; name++) {
        if (*name < '0' || *name > '9' || value > INT32_MAX / 10u)
            return 0;
        value = value * 10 + (unsigned)(*name - '0');
        if (value > INT32_MAX)
            return 0;
    }
    return (int)value;
}

static int values(const char* input, uint32_t wanted, size_t required, int* present) {
    size_t count = 0;
    while (*input) {
        while (*input == ' ' || *input == '\t' || *input == '\n')
            input++;
        if (!*input)
            break;
        uint64_t value = 0;
        const char* begin = input;
        while (*input >= '0' && *input <= '9') {
            value = value * 10 + (unsigned)(*input++ - '0');
            if (value >= UINT32_MAX)
                return failed(EUCLEAN);
        }
        if (input == begin || (*input && *input != ' ' && *input != '\t' && *input != '\n'))
            return failed(EUCLEAN);
        *present |= wanted != UINT32_MAX && value == wanted;
        if (++count > 65536)
            return failed(E2BIG);
    }
    return required && count != required ? failed(EUCLEAN) : 0;
}

static int status(int parent, const char* path, int tid, int group, uid_t uid, gid_t gid) {
    int fd = openat(parent, path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0)
        return errno == ENOENT || errno == ESRCH ? 0 : -1;
    struct statfs filesystem;
    int filesystem_error = fstatfs(fd, &filesystem) < 0 ? errno : 0;
    if (filesystem_error || filesystem.f_type != 0x9fa0) {
        close(fd);
        return failed(filesystem_error ? filesystem_error : ENODEV);
    }
    FILE* file = fdopen(fd, "r");
    if (!file) {
        int error = errno;
        close(fd);
        return failed(error);
    }
    char* line = NULL;
    size_t capacity = 0, total = 0;
    unsigned fields = 0;
    int error = 0, present = 0, vanished = 0;
    for (;;) {
        errno = 0;
        ssize_t count = getline(&line, &capacity, file);
        if (count < 0) {
            if (ferror(file)) {
                vanished = errno == ENOENT || errno == ESRCH;
                error = vanished ? 0 : errno ? errno : EIO;
            }
            break;
        }
        total += (size_t)count;
        if (total > 1024 * 1024 || memchr(line, 0, (size_t)count)) {
            error = E2BIG;
            break;
        }
        const char* input = NULL;
        unsigned bit = 0;
        uint32_t wanted = UINT32_MAX;
        size_t required = 4;
        if (!strncmp(line, "Uid:", 4)) {
            bit = 1;
            input = line + 4;
            wanted = uid;
        } else if (!strncmp(line, "Gid:", 4)) {
            bit = 2;
            input = line + 4;
            wanted = gid;
        } else if (!strncmp(line, "Groups:", 7)) {
            bit = 4;
            input = line + 7;
            wanted = gid;
            required = 0;
        } else if (!strncmp(line, "Pid:", 4)) {
            bit = 8;
            input = line + 4;
            wanted = (unsigned)tid;
            required = 1;
        } else if (!strncmp(line, "Tgid:", 5)) {
            bit = 16;
            input = line + 5;
            wanted = (unsigned)group;
            required = 1;
        }
        if (!bit)
            continue;
        int matched = 0;
        if ((fields & bit) || values(input, wanted, required, &matched) < 0 ||
            ((bit == 8 || bit == 16) && !matched)) {
            error = errno ? errno : EUCLEAN;
            break;
        }
        fields |= bit;
        if (bit < 8)
            present |= matched;
    }
    if (!error && !vanished && fields != 31)
        error = EUCLEAN;
    free(line);
    if (fclose(file) < 0 && !error)
        error = errno;
    return error ? failed(error) : vanished ? 0 : present;
}

int account_process_busy(uid_t uid, gid_t gid) {
    if (uid == (uid_t)-1 && gid == (gid_t)-1)
        return failed(EINVAL);
    DIR* root = opendir("/proc");
    if (!root)
        return -1;
    struct statfs filesystem;
    int error = fstatfs(dirfd(root), &filesystem) < 0 ? errno : 0;
    if (!error && filesystem.f_type != 0x9fa0)
        error = ENODEV;
    int present = 0;
    while (!error && !present) {
        errno = 0;
        struct dirent* entry = readdir(root);
        if (!entry) {
            error = errno;
            break;
        }
        int pid = numeric_pid(entry->d_name);
        if (!pid)
            continue;
        char path[64];
        snprintf(path, sizeof(path), "%d/status", pid);
        int result = status(dirfd(root), path, pid, pid, uid, gid);
        if (result < 0) {
            error = errno;
            break;
        }
        if (result) {
            present = 1;
            break;
        }
        snprintf(path, sizeof(path), "%d/task", pid);
        int fd = openat(dirfd(root), path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (fd < 0) {
            if (errno != ENOENT && errno != ESRCH)
                error = errno;
            continue;
        }
        DIR* threads = fdopendir(fd);
        if (!threads) {
            error = errno;
            close(fd);
            break;
        }
        while (!error && !present) {
            errno = 0;
            struct dirent* member = readdir(threads);
            if (!member) {
                error = errno;
                break;
            }
            int tid = numeric_pid(member->d_name);
            if (!tid || tid == pid)
                continue;
            snprintf(path, sizeof(path), "%d/status", tid);
            result = status(dirfd(threads), path, tid, pid, uid, gid);
            if (result < 0)
                error = errno;
            else
                present = result;
        }
        if (closedir(threads) < 0 && !error)
            error = errno;
    }
    if (closedir(root) < 0 && !error)
        error = errno;
    return error ? failed(error) : present;
}
