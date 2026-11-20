// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    userspace/tests/process/sysinfo.c
 * @brief   Exercise Linux system resource reporting.
 * @author  frankischilling
 * @date    2026-11-19
 *
 * Checks the syscall layout, physical allocation lifetime, and scheduler load in a guest.
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
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysinfo.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define CHECK(value)                                                                               \
    do {                                                                                           \
        if (!(value)) {                                                                            \
            fprintf(stderr, "SYSINFO_FAIL line=%d errno=%d expression=%s\n", __LINE__, errno,      \
                    #value);                                                                       \
            exit(1);                                                                               \
        }                                                                                          \
    } while (0)

enum { sysinfo_size = 112 };

// libc may reserve more space than the kernel copies.
_Static_assert(sizeof(struct sysinfo) >= sysinfo_size && offsetof(struct sysinfo, procs) == 80 &&
                   offsetof(struct sysinfo, mem_unit) == 104,
               "Linux x86-64 sysinfo fields");

static struct sysinfo read_info(void) {
    struct sysinfo info;
    CHECK(sysinfo(&info) == 0);
    CHECK(info.mem_unit == 1 && info.totalram > 0 && info.freeram <= info.totalram &&
          info.procs > 0);
    return info;
}

static void abi(void) {
    struct timespec before, after;
    CHECK(clock_gettime(CLOCK_BOOTTIME, &before) == 0);
    struct sysinfo info = read_info();
    CHECK(clock_gettime(CLOCK_BOOTTIME, &after) == 0);
    const unsigned long uptime = info.uptime;
    CHECK(uptime >= (unsigned long)before.tv_sec &&
          uptime <= (unsigned long)after.tv_sec + (after.tv_nsec != 0));

    const size_t page = (size_t)sysconf(_SC_PAGESIZE);
    char* mapping =
        mmap(NULL, page * 2, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(mapping != MAP_FAILED && mprotect(mapping + page, page, PROT_NONE) == 0);
    CHECK(syscall(SYS_sysinfo, NULL) == -1 && errno == EFAULT);
    CHECK(syscall(SYS_sysinfo, mapping + page - sysinfo_size) == 0);
    CHECK(syscall(SYS_sysinfo, mapping + page - sysinfo_size + 1) == -1 && errno == EFAULT);
    CHECK(munmap(mapping, page * 2) == 0);
    printf("SYSINFO_ABI_PASS ram=%lu uptime=%lu tasks=%u\n", info.totalram, uptime, info.procs);
}

static void guest_memory(void) {
    size_t bytes = 1024 * (size_t)sysconf(_SC_PAGESIZE);
    struct sysinfo before = read_info();
    volatile char* mapping =
        mmap(NULL, bytes, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(mapping != MAP_FAILED);
    mapping[0] = 1;
    mapping[bytes - 1] = 2;
    struct sysinfo mapped = read_info();
    CHECK(mapped.totalram == before.totalram && mapped.freeram + bytes <= before.freeram);
    CHECK(munmap((void*)mapping, bytes) == 0);
    CHECK(read_info().freeram >= mapped.freeram + bytes);

    before = read_info();
    int id = shmget(IPC_PRIVATE, bytes, IPC_CREAT | 0600);
    CHECK(id >= 0);
    void* shared = shmat(id, NULL, 0);
    CHECK(shared != (void*)-1);
    CHECK(read_info().sharedram == before.sharedram + bytes);
    CHECK(shmctl(id, IPC_RMID, NULL) == 0);
    CHECK(read_info().sharedram == before.sharedram + bytes);
    CHECK(shmdt(shared) == 0);
    CHECK(read_info().sharedram == before.sharedram);
    puts("SYSINFO_GUEST_MEMORY_PASS");
}

static void guest_shared_mapping(void) {
    const size_t bytes = 3 * (size_t)sysconf(_SC_PAGESIZE);
    const unsigned long before = read_info().sharedram;
    volatile char* shared =
        mmap(NULL, bytes, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    CHECK(shared != MAP_FAILED && read_info().sharedram == before + bytes);
    int ready[2];
    CHECK(pipe(ready) == 0);
    pid_t child = fork();
    CHECK(child >= 0);
    if (!child) {
        close(ready[1]);
        alarm(5);
        char signal;
        CHECK(read(ready[0], &signal, 1) == 1 && shared[bytes - 1] == signal);
        CHECK(read_info().sharedram == before + bytes);
        _exit(0);
    }
    close(ready[0]);
    const char value = 'm';
    shared[bytes - 1] = value;
    CHECK(munmap((void*)shared, bytes) == 0 && read_info().sharedram == before + bytes);
    CHECK(write(ready[1], &value, 1) == 1 && close(ready[1]) == 0);
    int status;
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    CHECK(read_info().sharedram == before);
    puts("SYSINFO_GUEST_SHARED_PASS");
}

static void guest_buffers(void) {
    struct sysinfo before = read_info();
    CHECK(before.bufferram == 0);
    CHECK(mkdir("/mnt", 0755) == 0);
    CHECK(mount("/dev/vda", "/mnt", "ext2", 0, NULL) == 0);
    CHECK(read_info().bufferram > before.bufferram);
    CHECK(umount("/mnt") == 0 && read_info().bufferram == before.bufferram);
    puts("SYSINFO_GUEST_BUFFERS_PASS");
}

static void guest_load(void) {
    struct sysinfo before = read_info();
    pid_t children[3];
    for (unsigned n = 0; n < sizeof(children) / sizeof(children[0]); n++) {
        pid_t pid = fork();
        CHECK(pid >= 0);
        if (pid == 0) {
            alarm(23);
            for (;;)
                __asm__ volatile("pause");
        }
        children[n] = pid;
    }
    CHECK(read_info().procs == before.procs + 3);
    CHECK(sleep(11) == 0);
    struct sysinfo busy = read_info();
    CHECK(busy.loads[0] > before.loads[0] && busy.loads[1] > before.loads[1] &&
          busy.loads[2] > before.loads[2]);
    for (unsigned n = 0; n < sizeof(children) / sizeof(children[0]); n++) {
        int status = 0;
        CHECK(kill(children[n], SIGTERM) == 0 && waitpid(children[n], &status, 0) == children[n]);
        CHECK(WIFSIGNALED(status) && WTERMSIG(status) == SIGTERM);
    }
    CHECK(read_info().procs == before.procs);
    CHECK(sleep(6) == 0);
    struct sysinfo idle = read_info();
    CHECK(idle.loads[0] < busy.loads[0] && idle.loads[1] < busy.loads[1] &&
          idle.loads[2] < busy.loads[2]);
    printf("SYSINFO_GUEST_LOAD_PASS busy=%lu/%lu/%lu idle=%lu/%lu/%lu\n", busy.loads[0],
           busy.loads[1], busy.loads[2], idle.loads[0], idle.loads[1], idle.loads[2]);
}

int main(int argc, char** argv) {
    CHECK(argc == 1 || (argc == 2 && strcmp(argv[1], "--guest") == 0));
    abi();
    if (argc == 2) {
        guest_memory();
        guest_shared_mapping();
        guest_buffers();
        guest_load();
    }
    puts("SYSINFO_PASS");
    return 0;
}
