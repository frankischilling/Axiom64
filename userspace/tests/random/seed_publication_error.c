// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int __real_renameat(int, const char*, int, const char*);

// Native failure fixture: the after mode performs the real Linux rename before
// reporting EIO. The before mode is a no-effect control. Neither is a disk fault.
int __wrap_renameat(int old_directory, const char* old_name, int new_directory,
                    const char* new_name) {
    const char* mode = getenv("AXIOM64_SEED_RENAME_ERROR");
    int publication = mode && !strncmp(old_name, "seed.tmp.", 9) && !strcmp(new_name, "seed");
    if (publication && !strcmp(mode, "before")) {
        puts("NATIVE_SEED_RENAME_ERROR phase=before kernel_called=0");
        errno = EIO;
        return -1;
    }
    int result = __real_renameat(old_directory, old_name, new_directory, new_name);
    if (publication && !strcmp(mode, "after") && result == 0) {
        puts("NATIVE_SEED_RENAME_ERROR phase=after kernel_called=1 kernel_result=0");
        errno = EIO;
        return -1;
    }
    return result;
}
