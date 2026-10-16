// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>

#define CHECK(value)                                                                               \
    do {                                                                                           \
        if (!(value)) {                                                                            \
            fprintf(stderr, "EXT2_JOURNAL_REJECT_FAIL line=%d errno=%d\n", __LINE__, errno);       \
            exit(1);                                                                               \
        }                                                                                          \
    } while (0)

int main(int argc, char** argv) {
    CHECK(argc == 2 && !getuid() && !geteuid());
    CHECK(mkdir("/mnt", 0755) == 0 || errno == EEXIST);
    CHECK(mkdir("/mnt/journal", 0755) == 0);
    int hardware = !strcmp(argv[1], "hardware");
    CHECK(hardware || !strcmp(argv[1], "invalid"));
    const int errors[] = {EOPNOTSUPP, EOPNOTSUPP, EUCLEAN, EUCLEAN,
                          EUCLEAN,    EUCLEAN,    EUCLEAN, EOPNOTSUPP};
    unsigned count = hardware ? 1 : sizeof(errors) / sizeof(errors[0]);
    for (unsigned index = 0; index < count; index++) {
        char device[] = "/dev/vda";
        device[7] = (char)('a' + index);
        errno = 0;
        CHECK(mount(device, "/mnt/journal", "ext2", MS_RDONLY, NULL) == -1);
        CHECK(errno == (hardware ? EROFS : errors[index]));
    }
    printf("EXT2_JOURNAL_REJECT_PASS mode=%s volumes=%u\n", argv[1], count);
    return 0;
}
