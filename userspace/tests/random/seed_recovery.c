// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/statfs.h>
#include <unistd.h>

#ifndef RANDOM_LINKAGE
#define RANDOM_LINKAGE "static"
#endif

static void require(int condition, const char* operation) {
    if (!condition) {
        fprintf(stderr, "RANDOM_SEED_RECOVERY_FAIL operation=%s error=%d\n", operation, errno);
        exit(1);
    }
}

static void rejected(const char* device, const char* type, unsigned long flags, const void* options,
                     int expected) {
    errno = 0;
    int result = mount(device, "/mnt/seed", type, flags, options);
    require(result == -1 && errno == expected, "rejected-mount");
    printf("RANDOM_SEED_RECOVERY_REJECT device=%s type=%s flags=%lu error=%d\n", device, type,
           flags, errno);
}

static void read_seed(void) {
    char bytes[64] = {0};
    int fd = open("/mnt/seed/seed.txt", O_RDONLY | O_CLOEXEC);
    const char* expected = "host-created seed\n";
    require(fd >= 0 && read(fd, bytes, sizeof(bytes)) == (ssize_t)strlen(expected) &&
                !strcmp(bytes, expected) && close(fd) == 0,
            "original-file-preserved");
}

static unsigned state(void) {
    unsigned char header[1536];
    int fd = open("/dev/vda", O_RDONLY | O_CLOEXEC);
    require(fd >= 0 && read(fd, header, sizeof(header)) == sizeof(header) && close(fd) == 0,
            "raw-state");
    return header[1082] | ((unsigned)header[1083] << 8);
}

static void reconciled(const char* device) {
    char marker[128] = {0};
    int fd = open(device, O_RDONLY | O_CLOEXEC);
    int repair, expected, precheck;
    unsigned free_blocks, free_inodes;
    require(fd >= 0 && read(fd, marker, sizeof(marker) - 1) == sizeof(marker) - 1 &&
                close(fd) == 0 &&
                sscanf(marker, "AXIOM64_EXT2_RECOVER=%d,%d,%u,%u,%d", &repair, &expected,
                       &free_blocks, &free_inodes, &precheck) == 5 &&
                repair == 1 && expected == EUCLEAN && precheck == EUCLEAN,
            "counter-volume-input");
    rejected(device, "ext2", 0, NULL, EUCLEAN);
    rejected(device, "ext2", MS_RDONLY, NULL, EUCLEAN);
    rejected(device, "ext2", MS_RDONLY, "recovery=check", EUCLEAN);
    require(mount(device, "/mnt/seed", "ext2", 0, "recovery=check") == 0,
            "counter-checked-writable-mount");
    struct statfs counts;
    require(statfs("/mnt/seed", &counts) == 0 && counts.f_bfree == free_blocks &&
                counts.f_ffree == free_inodes,
            "independent-counter-totals");
    read_seed();
    fd = open("/mnt/seed/counter-created", O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC, 0600);
    require(fd >= 0 && write(fd, "checked", 7) == 7 && fsync(fd) == 0 && close(fd) == 0 &&
                unlink("/mnt/seed/counter-created") == 0,
            "allocation-after-reconciliation");
    sync();
    require(statfs("/mnt/seed", &counts) == 0 && counts.f_bfree == free_blocks &&
                counts.f_ffree == free_inodes && umount("/mnt/seed") == 0,
            "counts-after-removal");
    require(mount(device, "/mnt/seed", "ext2", MS_RDONLY, NULL) == 0,
            "counter-clean-default-remount");
    read_seed();
    require(statfs("/mnt/seed", &counts) == 0 && counts.f_bfree == free_blocks &&
                counts.f_ffree == free_inodes && umount("/mnt/seed") == 0,
            "counter-clean-remount-totals");
    printf("RANDOM_SEED_RECOVERY_COUNTER device=%s free_blocks=%u free_inodes=%u\n", device,
           free_blocks, free_inodes);
}

int main(int argc, char** argv) {
    setbuf(stdout, NULL);
    require(argc >= 2 && argc <= 3, "arguments");
    unsigned checks = 0;
    if (!strcmp(argv[1], "policy")) {
        require(argc == 2, "policy-arguments");
        require(state() == 0, "actual-dirty-volume");
        rejected("/dev/vda", "ext2", 0, NULL, EUCLEAN);
        rejected("/dev/vda", "ext2", 0, "recovery=unknown", EINVAL);
        rejected("/dev/vda", "ext2", 0, (void*)1, EFAULT);
        rejected("/dev/vda", "ramfs", 0, "recovery=check", EINVAL);
        rejected("/dev/vda", "ext2", MS_REMOUNT, "recovery=check", EINVAL);
        require(mount("/dev/vda", "/mnt/seed", "ext2", MS_RDONLY, "recovery=check") == 0,
                "checked-readonly-mount");
        read_seed();
        require(umount("/mnt/seed") == 0 && state() == 0, "readonly-state-preserved");
        require(mount("/dev/vda", "/mnt/seed", "ext2", 0, "recovery=check") == 0,
                "checked-writable-mount");
        read_seed();
        require(umount("/mnt/seed") == 0 && state() == 1, "validated-clean-unmount");
        require(mount("/dev/vda", "/mnt/seed", "ext2", 0, NULL) == 0,
                "default-mount-after-clean-unmount");
        require(umount("/mnt/seed") == 0, "default-unmount");
        checks = 9;
    } else if (!strcmp(argv[1], "counters")) {
        require(argc == 3, "counter-arguments");
        unsigned volumes = (unsigned)strtoul(argv[2], NULL, 10);
        require(volumes > 0 && volumes <= 8, "counter-volume-count");
        for (unsigned index = 0; index < volumes; index++) {
            char device[16];
            snprintf(device, sizeof(device), "/dev/vd%c", 'a' + index);
            reconciled(device);
            checks++;
        }
    } else if (!strcmp(argv[1], "invalid")) {
        require(argc == 3, "invalid-arguments");
        unsigned volumes = (unsigned)strtoul(argv[2], NULL, 10);
        require(volumes > 0 && volumes <= 8, "invalid-volume-count");
        for (unsigned index = 0; index < volumes; index++) {
            char device[16], marker[512] = {0};
            snprintf(device, sizeof(device), "/dev/vd%c", 'a' + index);
            int fd = open(device, O_RDONLY | O_CLOEXEC), expected = 0;
            require(fd >= 0 && read(fd, marker, sizeof(marker)) == sizeof(marker) &&
                        close(fd) == 0 && sscanf(marker, "AXIOM64_EXT2_EXPECT=%d", &expected) == 1,
                    "damaged-volume-input");
            require(expected == EINVAL || expected == EOPNOTSUPP || expected == EUCLEAN,
                    "explicit-damaged-error");
            rejected(device, "ext2", 0, "recovery=check", expected);
            checks++;
        }
    } else {
        require(0, "mode");
    }
    printf("RANDOM_SEED_RECOVERY_PASS linkage=%s mode=%s checks=%u\n", RANDOM_LINKAGE, argv[1],
           checks);
    return 0;
}
