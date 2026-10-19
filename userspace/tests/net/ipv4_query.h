// SPDX-License-Identifier: GPL-3.0-or-later
#ifndef AXIOM64_TEST_IPV4_QUERY_H
#define AXIOM64_TEST_IPV4_QUERY_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/utsname.h>

static int ipv4_query_releases(void) {
    struct utsname identity;
    if (uname(&identity)) {
        perror("IPv4 query kernel identity");
        exit(1);
    }
    if (!strcmp(identity.sysname, "Axiom64"))
        return 1;
    unsigned major, minor;
    if (strcmp(identity.sysname, "Linux") ||
        sscanf(identity.release, "%u.%u", &major, &minor) != 2) {
        fprintf(stderr, "Unknown IPv4 query kernel identity\n");
        exit(1);
    }
    // Linux 6.7 moved these IP option accesses outside the socket lock.
    return major < 6 || (major == 6 && minor < 7);
}

#endif
