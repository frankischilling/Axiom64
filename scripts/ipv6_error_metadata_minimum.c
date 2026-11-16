// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#define IPV6_TEST_LABEL "IPV6_ERRORS"
#define IPV6_BARRIER_PROTOCOL 0x88bc
#define IPV6_BARRIER_MAGIC "IP6E"
#include "ipv6_fixture.h"

int ipv6_error_metadata_wire(const unsigned*, const unsigned char*, const int*);

int main(void) {
    int control = fixture_interfaces();
    check(!ipv6_error_metadata_wire(indices, &macs[0][0], packets),
          "metadata-only diagnostic");
    close(control);
    for (unsigned lane = 0; lane < 2; lane++)
        close(packets[lane]);
    puts("IPV6_ERRORS_METADATA_ONLY_COMPLETE");
}
