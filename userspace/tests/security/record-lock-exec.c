// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

// A separate executable proves that the lock observations happen after exec.
// The parent inspects the inode from a different file table before allowing exit.
int main(int argc, char** argv) {
    if (argc != 4)
        return 1;
    int file = atoi(argv[1]), ready = atoi(argv[2]), finish = atoi(argv[3]);
    char byte = 'x';
    if (fcntl(file, F_GETFD) < 0 || write(ready, &byte, 1) != 1 || read(finish, &byte, 1) != 1 ||
        byte != 'x')
        return 1;
    return 0;
}
