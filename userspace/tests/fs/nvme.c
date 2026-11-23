// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    userspace/tests/fs/nvme.c
 * @brief   Verify NVMe block nodes, data integrity, and persistent roots.
 * @author  frankischilling
 * @date    2026-11-21
 *
 * Runs from initramfs for disk I/O or from ext2 for root persistence checks.
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
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#ifndef BLKSSZGET
#define BLKSSZGET _IO(0x12, 104)
#endif
#ifndef BLKGETSIZE64
#define BLKGETSIZE64 _IOR(0x12, 114, uint64_t)
#endif

enum { sector = 512, disk_sectors = 8192 };

static const char payload[] = "NVMe persisted\n";

static int block(const char* path, uint64_t sectors, dev_t* number) {
    int fd = open(path, O_RDWR);
    struct stat status;
    uint64_t capacity;
    int size;
    if (fd < 0 || fstat(fd, &status) || !S_ISBLK(status.st_mode) || major(status.st_rdev) != 259 ||
        ioctl(fd, BLKGETSIZE64, &capacity) || capacity != sectors * sector ||
        ioctl(fd, BLKSSZGET, &size) || size != sector)
        return -1;
    *number = status.st_rdev;
    return fd;
}

static int faults(int fd) {
    static unsigned char bulk[33 * sector];
    char buffer[8];
    if (pread(fd, bulk, sizeof(bulk), 3099 * sector) != 32 * sector)
        return -1;
    if (pread(fd, buffer, sizeof(buffer), 3131 * sector) != -1 || errno != EIO)
        return -1;
    if (pread(fd, buffer, sizeof(buffer), 3132 * sector) != sizeof(buffer) ||
        memcmp(buffer, "ATA-READ", sizeof(buffer)))
        return -1;
    if (pwrite(fd, payload, sizeof(payload), 3133 * sector) != -1 || errno != EIO)
        return -1;
    return pwrite(fd, payload, sizeof(payload), 3134 * sector) != sizeof(payload) || fsync(fd);
}

static int transfer_sizes(int fd, unsigned first) {
    static unsigned char buffer[33 * sector], expected[sizeof(buffer)];
    const unsigned lengths[] = {8, 16, 24, 33};
    for (unsigned i = 0; i < sizeof(lengths) / sizeof(lengths[0]); ++i) {
        size_t bytes = lengths[i] * sector;
        off_t offset = (off_t)(first + i * 64) * sector;
        for (size_t j = 0; j < bytes; ++j)
            expected[j] = (unsigned char)(j * 17 + first + i);
        if (pwrite(fd, expected, bytes, offset) != (ssize_t)bytes || fdatasync(fd))
            return -1;
        if (pread(fd, buffer, bytes, offset) != (ssize_t)bytes || memcmp(buffer, expected, bytes))
            return -1;
    }
    for (unsigned i = 0; i < 65; ++i) {
        if (pread(fd, buffer, sector, (off_t)first * sector) != sector ||
            buffer[0] != (unsigned char)first)
            return -1;
    }
    return 0;
}

static int partition_inventory(const dev_t* numbers) {
    static const char* const names[] = {"nvme0n1", "nvme0n1p1", "nvme0n7", "nvme1n5"};
    static const unsigned sizes[] = {4096, 2048, 4096, 4096};
    const unsigned count = sizeof(names) / sizeof(names[0]);
    FILE* file = fopen("/proc/partitions", "r");
    if (!file)
        return -1;
    char line[100], name[32];
    unsigned actual_major, actual_minor, found = 0;
    unsigned long long kib;
    int valid = fgets(line, sizeof(line), file) && !strcmp(line, "major minor  #blocks  name\n");
    while (valid && fgets(line, sizeof(line), file)) {
        if (sscanf(line, "%u %u %llu %31s", &actual_major, &actual_minor, &kib, name) != 4 ||
            strncmp(name, "nvme", 4))
            continue;
        unsigned i = 0;
        while (i < count && strcmp(name, names[i]))
            ++i;
        if (i == count || (found & (1u << i)) || kib != sizes[i] ||
            actual_major != major(numbers[i]) || actual_minor != minor(numbers[i])) {
            valid = 0;
            break;
        }
        found |= 1u << i;
    }
    valid = valid && !ferror(file) && found == (1u << count) - 1;
    return fclose(file) || !valid;
}

static int identity_field(const char* path, const char* expected) {
    struct stat status;
    char value[64];
    const int fd = open(path, O_RDONLY);
    if (fd < 0)
        return -1;
    ssize_t size = read(fd, value, sizeof(value) - 1);
    const int valid = !fstat(fd, &status) && S_ISREG(status.st_mode) &&
                      (status.st_mode & 0777) == 0444 && size > 1 && value[size - 1] == '\n';
    if (close(fd) || !valid)
        return -1;
    value[size - 1] = 0;
    return expected && strcmp(value, expected) ? -1 : 0;
}

static int controller_inventory(void) {
    return identity_field("/sys/class/nvme/nvme0/serial", "AXNVME0") ||
           identity_field("/sys/class/nvme/nvme1/serial", "AXNVME1") ||
           identity_field("/sys/class/nvme/nvme0/model", "QEMU NVMe Ctrl") ||
           identity_field("/sys/class/nvme/nvme1/model", "QEMU NVMe Ctrl") ||
           identity_field("/sys/class/nvme/nvme0/firmware_rev", NULL) ||
           identity_field("/sys/class/nvme/nvme1/firmware_rev", NULL);
}

static int exclusive_claim(int partition) {
    const char* disk = "/dev/nvme0n1";
    const char* part = "/dev/nvme0n1p1";
    const int fd = open(disk, O_RDWR | O_EXCL);
    if (fd < 0 || open(part, O_RDONLY | O_EXCL) != -1 || errno != EBUSY ||
        open(part, O_RDWR) != -1 || errno != EBUSY ||
        mount(part, "/tmp", "ext2", MS_RDONLY, NULL) != -1 || errno != EBUSY)
        return -1;
    int copy = dup(fd);
    if (copy < 0 || close(fd) || open(disk, O_RDONLY | O_EXCL) != -1 || errno != EBUSY ||
        pwrite(partition, payload, 1, 3) != -1 || errno != EBUSY ||
        pwrite(copy, payload, sizeof(payload), 2048 * sector + 3) != sizeof(payload) || fsync(copy))
        return -1;
    int other = open("/dev/nvme0n7", O_RDONLY | O_EXCL);
    if (other < 0 || close(other) || close(copy))
        return -1;
    int released = open(part, O_RDONLY | O_EXCL);
    if (released < 0 || close(released))
        return -1;
    puts("NVME_EXCLUSIVE_CLAIM_PASS whole partition mount write dup release");
    return 0;
}

static int data(void) {
    struct stat missing;
    if (stat("/dev/nvme0n3", &missing) != -1 || errno != ENOENT ||
        stat("/dev/nvme0n2", &missing) != -1 || errno != ENOENT ||
        stat("/dev/nvme0n9", &missing) != -1 || errno != ENOENT)
        return -1;
    dev_t numbers[4];
    const int whole = block("/dev/nvme0n1", disk_sectors, &numbers[0]);
    const int part = block("/dev/nvme0n1p1", 4096, &numbers[1]);
    const int sparse_id = block("/dev/nvme0n7", disk_sectors, &numbers[2]);
    const int other = block("/dev/nvme1n5", disk_sectors, &numbers[3]);
    if (whole < 0 || part < 0 || sparse_id < 0 || other < 0)
        return -1;
    if (partition_inventory(numbers) || controller_inventory())
        return -1;
    for (unsigned i = 0; i < 4; ++i)
        for (unsigned j = i + 1; j < 4; ++j)
            if (numbers[i] == numbers[j])
                return -1;
    char sample[sizeof(payload)];
    if (pread(part, sample, 8, 0) != 8 || memcmp(sample, "ATA-SEED", 8) || faults(whole))
        return -1;
    if (pwrite(part, payload, sizeof(payload), 3) != sizeof(payload) || fsync(part) ||
        pread(whole, sample, sizeof(sample), 2048 * sector + 3) != sizeof(sample) ||
        memcmp(sample, payload, sizeof(sample)))
        return -1;
    const off_t end = 4096 * sector;
    if (pwrite(part, payload, sizeof(payload), end - 3) != 3 ||
        pwrite(part, payload, 1, end) != -1 || errno != ENOSPC ||
        pread(part, sample, 1, end) != 0 || fsync(part))
        return -1;
    if (exclusive_claim(part) || transfer_sizes(sparse_id, 128) || transfer_sizes(other, 256) ||
        close(whole) || close(part) || close(sparse_id) || close(other))
        return -1;
    puts("NVME_DATA_PASS sparse_ids two_controllers io_errors queue_wrap transfer_boundaries");
    return 0;
}

static int sparse_file(void) {
    enum { block_size = 4096 };

    const char* path = "/nvme-sparse";
    const unsigned char left = 0x53, right = 0xb4;
    unsigned char data[block_size], expected[block_size] = {0};
    const int fd = open(path, O_CREAT | O_EXCL | O_RDWR, 0600);
    if (fd < 0 || pwrite(fd, &left, 1, 0) != 1 || pwrite(fd, &right, 1, 2 * block_size + 3) != 1 ||
        fsync(fd))
        return -1;
    expected[0] = left;
    if (pread(fd, data, sizeof(data), 0) != sizeof(data) || memcmp(data, expected, sizeof(data)))
        return -1;
    expected[0] = 0;
    if (pread(fd, data, sizeof(data), block_size) != sizeof(data) ||
        memcmp(data, expected, sizeof(data)))
        return -1;
    expected[3] = right;
    if (pread(fd, data, sizeof(data), 2 * block_size) != 4 || memcmp(data, expected, 4))
        return -1;
    expected[3] = 0;
    if (ftruncate(fd, block_size + 19) || ftruncate(fd, 3 * block_size) || fsync(fd) ||
        pread(fd, data, sizeof(data), 2 * block_size) != sizeof(data) ||
        memcmp(data, expected, sizeof(data)) || close(fd) || unlink(path))
        return -1;
    puts("NVME_SPARSE_READ_PASS hole eof truncate");
    return 0;
}

static int root(void) {
    const char* disk = access("/dev/nvme0n1", F_OK) == 0 ? "/dev/nvme0n1" : "/dev/nvme0n7";
    if (open(disk, O_RDONLY | O_EXCL) != -1 || errno != EBUSY)
        return -1;
    int fd = open("/nvme-written", O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd >= 0) {
        if (write(fd, payload, sizeof(payload)) != sizeof(payload) || fsync(fd) || close(fd))
            return -1;
        if (sparse_file())
            return -1;
        puts("NVME_ROOT_WRITE_PASS");
        return 0;
    }
    if (errno != EEXIST)
        return -1;
    char buffer[sizeof(payload)];
    fd = open("/nvme-written", O_RDONLY);
    if (fd < 0 || read(fd, buffer, sizeof(buffer)) != sizeof(buffer) ||
        memcmp(buffer, payload, sizeof(payload)) || close(fd))
        return -1;
    puts("NVME_ROOT_REBOOT_PASS");
    return 0;
}

int main(void) {
    const int marker = open("/nvme-root", O_RDONLY);
    const int result = marker >= 0 ? close(marker) || root() : data();
    if (result) {
        perror("NVMe guest check");
        return 1;
    }
    fflush(stdout);
    reboot(RB_POWER_OFF);
    return 1;
}
