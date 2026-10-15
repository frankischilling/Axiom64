// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include "../../accounts/logbook_internal.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int destination = -1;
static unsigned mode, calls;
ssize_t __real_write(int, const void*, size_t);

ssize_t __wrap_write(int fd, const void* bytes, size_t count) {
    if (fd == destination) {
        calls++;
        if ((mode == 1 && calls == 1) || (mode == 2 && calls == 2)) {
            errno = mode == 1 ? EINTR : EIO;
            return -1;
        }
        if (mode == 3 && calls == 1)
            return 0;
        if (mode == 1 && count > 17)
            count = 17;
    }
    return __real_write(fd, bytes, count);
}

static void path(char output[4096], const char* directory, const char* name) {
    int count = snprintf(output, 4096, "%s/%s", directory, name);
    assert(count > 0 && count < 4096);
}

int main(int argc, char** argv) {
    assert(argc == 2);
    struct account_logbook book = {0};
    book.state.generation = 1;
    book.count = 128;
    book.frames = calloc(book.count, sizeof(*book.frames));
    assert(book.frames);

    static const enum account_login_kind kinds[] = {ACCOUNT_LOGIN_START, ACCOUNT_LOGIN_DENIED,
                                                    ACCOUNT_LOGIN_SUDO, ACCOUNT_LOGIN_END};

    for (size_t i = 0; i < book.count; i++) {
        unsigned session = (unsigned)i / 4;
        char name[33], terminal[32];
        assert(snprintf(name, sizeof(name), "user%u", session) > 0);
        assert(snprintf(terminal, sizeof(terminal), "/dev/pts/%u", session) > 0);
        unsigned char token[16] = {0};
        token[0] = (unsigned char)(session + 1);
        enum account_login_kind kind = kinds[i % 4];
        assert(account_login_frame_make(
                   &book.frames[i], kind, name, 70000 + session, 80000, 10000 + (pid_t)session,
                   terminal, "root", 0,
                   kind == ACCOUNT_LOGIN_START || kind == ACCOUNT_LOGIN_END ? token : NULL) == 0);
        book.frames[i].seconds = 1750000000 + session;
        book.frames[i].entry.seconds = 1750000000 + (int32_t)session;
        book.frames[i].entry.microseconds = 123456;
        account_login_frame_seal(&book.frames[i], i + 1);
    }
    char filename[4096];
    path(filename, argv[1], "frames.bin");
    FILE* frames = fopen(filename, "wb");
    assert(frames && fwrite(book.frames, sizeof(*book.frames), book.count, frames) == book.count &&
           fclose(frames) == 0);
    for (unsigned kind = 0; kind < 4; kind++) {
        struct account_logbook_projection projection = {&book, kind};
        for (mode = 0; mode < 4; mode++) {
            char name[64];
            assert(snprintf(name, sizeof(name), "projection-%u-%u.bin", kind, mode) > 0);
            path(filename, argv[1], name);
            destination = open(filename, O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC, 0600);
            assert(destination >= 0);
            calls = 0;
            errno = 0;
            int result = account_logbook_write_projection(destination, &projection);
            int error = errno;
            off_t size = lseek(destination, 0, SEEK_END);
            assert(size >= 0 && close(destination) == 0);
            destination = -1;
            printf("ACCOUNT_PROJECTION kind=%u mode=%u result=%d errno=%d bytes=%lld calls=%u\n",
                   kind, mode, result, error, (long long)size, calls);
        }
    }
    path(filename, argv[1], "frames-after.bin");
    frames = fopen(filename, "wb");
    assert(frames && fwrite(book.frames, sizeof(*book.frames), book.count, frames) == book.count &&
           fclose(frames) == 0);
    free(book.frames);
    return 0;
}
