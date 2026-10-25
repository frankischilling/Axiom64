// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include "../tcp_maxseg.h"
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>

int main(int argc, char** argv) {
    int native = argc == 2 && !strcmp(argv[1], "--native");
    if (argc != 1 && !native) {
        fprintf(stderr, "usage: %s [--native]\n", argv[0]);
        return 2;
    }
    tcp_maxseg_options_family(native, AF_INET6);
    return 0;
}
