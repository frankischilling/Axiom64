// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    userspace/tests/fs/legacy-ata.c
 * @brief   Exercise ATA and SATA block nodes and persistent roots.
 * @author  frankischilling
 * @date    2026-11-21
 *
 * Checks sector addressing, flush, partition bounds, and persistence after reboot.
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
#include <string.h>
#include <sys/ioctl.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#define BLKSSZGET _IO(0x12, 104)
#define BLKGETSIZE64 _IOR(0x12, 114, size_t)

enum { sector = 512 };

static const off_t boundary = (off_t)(1u << 28) * sector;
static const char payload[] = "ATA persisted\n";

static int block(const char* path, unsigned expected_major, unsigned expected_minor,
                 uint64_t bytes) {
    int fd = open(path, O_RDWR);
    struct stat st;
    uint64_t size;
    int unit;
    if (fd < 0 || fstat(fd, &st) || !S_ISBLK(st.st_mode) || major(st.st_rdev) != expected_major ||
        minor(st.st_rdev) != expected_minor || ioctl(fd, BLKGETSIZE64, &size) || size != bytes ||
        ioctl(fd, BLKSSZGET, &unit) || unit != sector)
        return -1;
    return fd;
}

static int check_faults(int fd) {
    char data[8];
    errno = 0;
    ssize_t result = pread(fd, data, sizeof(data), 3131 * sector);
    if (result != -1 || errno != EIO) {
        fprintf(stderr, "ATA read fault: result=%zd errno=%d\n", result, errno);
        return -1;
    }
    if (pread(fd, data, sizeof(data), 3132 * sector) != sizeof(data) || memcmp(data, "ATA-READ", 8))
        return -1;
    errno = 0;
    result = pwrite(fd, payload, sizeof(payload), 3133 * sector);
    if (result != -1 || errno != EIO) {
        fprintf(stderr, "ATA write fault: result=%zd errno=%d\n", result, errno);
        return -1;
    }
    return pwrite(fd, payload, sizeof(payload), 3134 * sector) != sizeof(payload) || fsync(fd);
}

static int check_data(void) {
    struct stat st;
#ifdef AXIOM64_AHCI_TEST
    const char* absent = "/dev/sdd";
    const char* secondary_name = "/dev/sdc";
    const unsigned secondary_minor = 32;
#else
    const char* absent = "/dev/sdc";
    const char* secondary_name = "/dev/sdd";
    const unsigned secondary_minor = 48;
#endif
    if (stat(absent, &st) != -1 || errno != ENOENT)
        return -1;
    int primary = block("/dev/sda", 8, 0, 8192 * sector);
    int partition = block("/dev/sda1", 8, 1, 4096 * sector);
    int slave = block("/dev/sdb", 8, 16, boundary + 64 * sector);
    int secondary = block(secondary_name, 8, secondary_minor, 4096 * sector);
    int virtio = block("/dev/vda", 252, 0, 4096 * sector);
    char buffer[2 * sector];
    if (primary < 0 || partition < 0 || slave < 0 || secondary < 0 || virtio < 0 ||
        pread(partition, buffer, 8, 0) != 8 || memcmp(buffer, "ATA-SEED", 8) ||
        pread(secondary, buffer, 8, 0) != 8 || memcmp(buffer, "ATA-SEC2", 8) ||
        pread(virtio, buffer, 8, 0) != 8 || memcmp(buffer, "VIO-SEED", 8))
        return -1;
    if (check_faults(primary))
        return -1;
#ifdef AXIOM64_AHCI_TEST
    unsigned char many[33 * sector];
    memset(many, 0xa7, sizeof(many));
    if (pwrite(secondary, many, sizeof(many), 128 * sector) != sizeof(many) || fsync(secondary))
        return -1;
    memset(many, 0, sizeof(many));
    if (pread(secondary, many, sizeof(many), 128 * sector) != sizeof(many))
        return -1;
    for (size_t i = 0; i < sizeof(many); ++i)
        if (many[i] != 0xa7)
            return -1;
    puts("AHCI_MULTISECTOR_PASS");
#endif
    if (pwrite(partition, payload, sizeof(payload), 3) != sizeof(payload) || fsync(partition) ||
        pread(primary, buffer, sizeof(payload), 2048 * sector + 3) != sizeof(payload) ||
        memcmp(buffer, payload, sizeof(payload)))
        return -1;

    memset(buffer, 0xa5, sector);
    memset(buffer + sector, 0x6b, sector);
    if (pwrite(slave, buffer, sizeof(buffer), boundary - sector) != sizeof(buffer) ||
        fdatasync(slave))
        return -1;
    memset(buffer, 0, sizeof(buffer));
    if (pread(slave, buffer, sizeof(buffer), boundary - sector) != sizeof(buffer))
        return -1;
    for (size_t i = 0; i < sizeof(buffer); ++i)
        if ((unsigned char)buffer[i] != (i < sector ? 0xa5 : 0x6b))
            return -1;

    off_t end = 4096 * sector;
    if (pwrite(partition, payload, sizeof(payload), end - 3) != 3 ||
        pwrite(partition, payload, 1, end) != -1 || errno != ENOSPC ||
        pread(partition, buffer, 1, end) != 0 || fsync(partition) || close(primary) ||
        close(partition) || close(slave) || close(secondary) || close(virtio))
        return -1;
    puts("ATA_BLOCK_PASS");
    return 0;
}

static int check_root(void) {
#ifdef AXIOM64_AHCI_TEST
    char probe[8];
    int first = open("/dev/sda", O_RDONLY);
    if (first < 0)
        return -1;
    ssize_t length = pread(first, probe, sizeof(probe), 0);
    if (close(first) || length != sizeof(probe))
        return -1;
    if (!memcmp(probe, "PATA-MIX", sizeof(probe))) {
        struct stat st;
        if (stat("/dev/sdb1", &st) || !S_ISBLK(st.st_mode) || major(st.st_rdev) != 8 ||
            minor(st.st_rdev) != 17)
            return -1;
        puts("AHCI_MIXED_NAMES_PASS");
    }
#endif
    char buffer[sizeof(payload)] = {0};
    int fd = open("/ata-written", O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd >= 0) {
        if (write(fd, payload, sizeof(payload)) != sizeof(payload) || fsync(fd) || close(fd))
            return -1;
        puts("ATA_ROOT_WRITE_PASS");
        return 0;
    }
    if (errno != EEXIST)
        return -1;
    fd = open("/ata-written", O_RDONLY);
    if (fd < 0 || read(fd, buffer, sizeof(buffer)) != sizeof(buffer) ||
        memcmp(buffer, payload, sizeof(payload)) || close(fd))
        return -1;
    puts("ATA_ROOT_REBOOT_PASS");
    return 0;
}

int main(void) {
    int fixture = open("/ata-root", O_RDONLY);
    int result = fixture >= 0 ? close(fixture) || check_root() : check_data();
    if (result) {
        perror("ATA guest check");
        return 1;
    }
    fflush(stdout);
    reboot(RB_POWER_OFF);
    return 1;
}
