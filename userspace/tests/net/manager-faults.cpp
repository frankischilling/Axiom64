// SPDX-License-Identifier: GPL-3.0-or-later
// Linked only into the fault-test manager. Surrounding calls use actual files
// and sockets; the normal installed manager has no injected-failure behavior.
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

namespace {
int hint_directory = -1;

bool selected(const char* name) {
    const char* value = getenv("MANAGER_FAULT");
    return value && !strcmp(value, name);
}

int fail(const char* operation) {
    fprintf(stderr, "MANAGER_FAULT_INJECT operation=%s errno=%d\n", operation, EIO);
    errno = EIO;
    return -1;
}
} // namespace

extern "C" int __real_renameat(int, const char*, int, const char*);
extern "C" int __real_fsync(int);
extern "C" int __real_rename(const char*, const char*);
extern "C" int __real_unlinkat(int, const char*, int);
extern "C" int __real_close(int);

extern "C" int __wrap_renameat(int olddir, const char* oldname, int newdir, const char* newname) {
    int result = __real_renameat(olddir, oldname, newdir, newname);
    if (!result && selected("hint-sync") && !strcmp(newname, "eth0.lease"))
        hint_directory = newdir;
    return result;
}

extern "C" int __wrap_fsync(int descriptor) {
    if (descriptor == hint_directory) {
        hint_directory = -1;
        return fail("hint-sync");
    }
    return __real_fsync(descriptor);
}

extern "C" int __wrap_rename(const char* before, const char* after) {
    const char* leaf = strrchr(after, '/');
    if (selected("resolver") && leaf && !strcmp(leaf + 1, "resolv.conf")) {
        int fd = open(before, O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
        if (fd >= 0) {
            char bytes[1025];
            ssize_t size = read(fd, bytes, sizeof(bytes) - 1);
            __real_close(fd);
            if (size >= 0) {
                bytes[size] = 0;
                if (strstr(bytes, "nameserver 10.23.1.53\n")) {
                    return fail("resolver");
                }
            }
        }
    }
    return __real_rename(before, after);
}

extern "C" int __wrap_unlinkat(int directory, const char* leaf, int flags) {
    if (selected("hint-remove") && !strcmp(leaf, "eth0.lease")) {
        return fail("hint-remove");
    }
    return __real_unlinkat(directory, leaf, flags);
}

extern "C" int __wrap_close(int descriptor) {
    sockaddr_in endpoint{};
    socklen_t size = sizeof(endpoint);
    bool inject = selected("close") &&
                  getsockname(descriptor, reinterpret_cast<sockaddr*>(&endpoint), &size) == 0 &&
                  size == sizeof(endpoint) && endpoint.sin_family == AF_INET &&
                  endpoint.sin_port == htons(68);
    int result = __real_close(descriptor);
    if (!result && inject) {
        return fail("close");
    }
    return result;
}
