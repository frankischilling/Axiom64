// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    userspace/tests/abi/mincore.c
 * @brief   Exercise Linux mincore on anonymous and file mappings.
 * @author  frankischilling
 * @date    2026-11-23
 *
 * Checks residency, error reporting, cache aliases, and permission masking.
 *
 * Copyright (C) 2026 frankischilling
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://gnu.org/licenses/>.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHECK(condition)                                                                           \
    do {                                                                                           \
        if (!(condition)) {                                                                        \
            fprintf(stderr, "MINCORE_FAIL line=%d errno=%d %s\n", __LINE__, errno, #condition);    \
            exit(1);                                                                               \
        }                                                                                          \
    } while (0)

enum { page_size = 4096, anonymous = MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE };

static void anonymous_residency(void) {
    volatile unsigned char* memory =
        mmap(NULL, 3 * page_size, PROT_READ | PROT_WRITE, anonymous, -1, 0);
    unsigned char* start = (unsigned char*)memory;
    unsigned char vec[] = {0x55, 0x55, 0x55, 0x55};
    CHECK(start != MAP_FAILED);
    memory[0] = 42;
    CHECK(mprotect(start, page_size, PROT_NONE) == 0);
    CHECK(mincore(start, 2 * page_size + 1, vec) == 0);
    CHECK(vec[0] == 1 && vec[1] == 0 && vec[2] == 0 && vec[3] == 0x55);

    CHECK(mincore(start + 1, 0, NULL) == -1 && errno == EINVAL);
    CHECK(mincore(start, 0, NULL) == 0);
    CHECK(mincore(start, SIZE_MAX, vec) == -1 && errno == ENOMEM);
    CHECK(mincore(start, page_size, NULL) == -1 && errno == EFAULT);
    CHECK(mincore(start, page_size, start) == -1 && errno == EFAULT);

    CHECK(munmap(start + page_size, page_size) == 0);
    vec[0] = vec[1] = 0x55;
    CHECK(mincore(start, 3 * page_size, vec) == -1 && errno == ENOMEM);
    CHECK(vec[0] == 1 && vec[1] == 0x55);
    CHECK(munmap(start, 3 * page_size) == 0);
    CHECK(mincore(start, page_size, vec) == -1 && errno == ENOMEM);
    puts("MINCORE_ANONYMOUS_PASS");
}

static void long_vector(void) {
    const size_t pages = 4097, length = pages * page_size;
    volatile unsigned char* memory = mmap(NULL, length, PROT_READ | PROT_WRITE, anonymous, -1, 0);
    unsigned char* vector = malloc(pages + 1);
    CHECK(memory != MAP_FAILED && vector);
    memory[0] = 1;
    memory[length - 1] = 2;
    vector[pages] = 0x55;
    CHECK(mincore((void*)memory, length, vector) == 0);
    CHECK(vector[0] == 1 && vector[pages - 1] == 1 && vector[pages] == 0x55);
    for (size_t i = 1; i < pages - 1; ++i)
        CHECK(vector[i] == 0);
    CHECK(munmap((void*)memory, length) == 0);
    free(vector);
    puts("MINCORE_LONG_VECTOR_PASS");
}

static void memory_file(void) {
    const size_t length = 2 * page_size;
    const int fd = memfd_create("mincore", 0);
    CHECK(fd >= 0 && ftruncate(fd, length) == 0);
    unsigned char* shared = mmap(NULL, length, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    volatile unsigned char* private =
        mmap(NULL, length, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    CHECK(shared != MAP_FAILED && private != MAP_FAILED);
    unsigned char vec[2];
    CHECK(mincore(shared, length, vec) == 0 && vec[0] == 0 && vec[1] == 0);

    CHECK(pwrite(fd, "a", 1, page_size) == 1);
    CHECK(mincore(shared, length, vec) == 0 && vec[0] == 0 && vec[1] == 1);
    private[page_size] = 'b';
    CHECK(mincore((void*)private, length, vec) == 0 && vec[0] == 0 && vec[1] == 1);
    CHECK(shared[page_size] == 'a' && private[page_size] == 'b');
    CHECK(munmap((void*)private, length) == 0 && munmap(shared, length) == 0 && close(fd) == 0);
    puts("MINCORE_MEMFD_PASS");
}

static void file_residency(void) {
    char path[] = "mincore-file-XXXXXX";
    const int fd = mkstemp(path);
    CHECK(fd >= 0 && ftruncate(fd, 2 * page_size) == 0);
    unsigned char* view = mmap(NULL, 3 * page_size, PROT_READ, MAP_PRIVATE, fd, 0);
    volatile unsigned char* alias = mmap(NULL, page_size, PROT_READ, MAP_PRIVATE, fd, page_size);
    CHECK(view != MAP_FAILED && alias != MAP_FAILED);
    unsigned char vec[3];
    CHECK(mincore(view, 3 * page_size, vec) == 0 && vec[1] == 0 && vec[2] == 0);
    CHECK(alias[0] == 0);
    CHECK(mincore(view, 3 * page_size, vec) == 0 && vec[1] == 1 && vec[2] == 0);
    CHECK(fchmod(fd, 0444) == 0);

    if (geteuid() == 0) {
        pid_t child = fork();
        CHECK(child >= 0);
        if (!child) {
            CHECK(setgid(12345) == 0 && setuid(12345) == 0);
            CHECK(mincore(view, 3 * page_size, vec) == 0 && vec[0] == 1 && vec[1] == 1 &&
                  vec[2] == 1);
            _exit(0);
        }
        int status;
        CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
        CHECK(fchmod(fd, 0666) == 0);
        child = fork();
        CHECK(child >= 0);
        if (!child) {
            CHECK(setgid(12345) == 0 && setuid(12345) == 0);
            CHECK(mincore(view, 3 * page_size, vec) == 0 && vec[1] == 1 && vec[2] == 0);
            _exit(0);
        }
        CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
        puts("MINCORE_FILE_PRIVACY_PASS");
    }
    CHECK(munmap((void*)alias, page_size) == 0 && munmap(view, 3 * page_size) == 0);
    CHECK(close(fd) == 0 && unlink(path) == 0);
    puts("MINCORE_FILE_PASS");
}

int main(void) {
    CHECK(sysconf(_SC_PAGESIZE) == page_size);
    anonymous_residency();
    long_vector();
    memory_file();
    file_residency();
    puts("MINCORE_PASS");
    return 0;
}
