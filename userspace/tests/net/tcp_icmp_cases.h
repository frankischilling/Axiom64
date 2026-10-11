// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

enum icmp_mode {
    ICMP_PENDING,
    ICMP_IGNORE,
    ICMP_BLOCKING,
    ICMP_INTERRUPT,
    ICMP_RETAINED,
    ICMP_RETRY,
    ICMP_SOFT,
    ICMP_CONSUME,
    ICMP_RECOVER,
    ICMP_TIME_WAIT,
    ICMP_PASSIVE_KEEP,
    ICMP_PASSIVE_DROP
};

struct icmp_case {
    const char* name;
    unsigned type, code;
    const char* mutation;
    enum icmp_mode mode;
    int error;
};

// The independently constructed peer reads this literal acceptance table too.
static const struct icmp_case icmp_cases[] = {
    {"network", 3, 0, "valid", ICMP_PENDING, 101},
    {"host", 3, 1, "valid", ICMP_PENDING, 113},
    {"protocol", 3, 2, "valid", ICMP_PENDING, 92},
    {"port", 3, 3, "valid", ICMP_PENDING, 111},
    {"source-route", 3, 5, "valid", ICMP_PENDING, 95},
    {"network-unknown", 3, 6, "valid", ICMP_PENDING, 101},
    {"host-unknown", 3, 7, "valid", ICMP_PENDING, 112},
    {"isolated", 3, 8, "valid", ICMP_PENDING, 64},
    {"network-admin", 3, 9, "valid", ICMP_PENDING, 101},
    {"host-admin", 3, 10, "valid", ICMP_PENDING, 113},
    {"network-tos", 3, 11, "valid", ICMP_PENDING, 101},
    {"host-tos", 3, 12, "valid", ICMP_PENDING, 113},
    {"filtered", 3, 13, "valid", ICMP_PENDING, 113},
    {"precedence", 3, 14, "valid", ICMP_PENDING, 113},
    {"cutoff", 3, 15, "valid", ICMP_PENDING, 113},
    {"ttl", 11, 0, "valid", ICMP_PENDING, 113},
    {"reassembly", 11, 1, "valid", ICMP_IGNORE, 0},
    {"parameter", 12, 0, "valid", ICMP_PENDING, 71},
    {"option", 12, 1, "valid", ICMP_PENDING, 71},
    {"length", 12, 2, "valid", ICMP_PENDING, 71},
    {"ip-options", 3, 3, "options", ICMP_PENDING, 111},
    {"inclusive-edge", 3, 3, "upper-edge", ICMP_PENDING, 111},
    {"weak-host", 3, 3, "other-device", ICMP_PENDING, 111},
    {"bad-icmp-checksum", 3, 3, "icmp-checksum", ICMP_IGNORE, 0},
    {"bad-ip-checksum", 3, 3, "quote-checksum", ICMP_IGNORE, 0},
    {"truncated", 3, 3, "truncated", ICMP_IGNORE, 0},
    {"short-original", 3, 3, "short-original", ICMP_IGNORE, 0},
    {"bad-version", 3, 3, "version", ICMP_IGNORE, 0},
    {"bad-ihl", 3, 3, "ihl", ICMP_IGNORE, 0},
    {"fragment-offset", 3, 3, "fragment", ICMP_IGNORE, 0},
    {"more-fragments", 3, 3, "more-fragments", ICMP_IGNORE, 0},
    {"reserved-flag", 3, 3, "reserved", ICMP_IGNORE, 0},
    {"wrong-protocol", 3, 3, "protocol", ICMP_IGNORE, 0},
    {"wrong-local", 3, 3, "local", ICMP_IGNORE, 0},
    {"wrong-peer", 3, 3, "peer", ICMP_IGNORE, 0},
    {"wrong-local-port", 3, 3, "source-port", ICMP_IGNORE, 0},
    {"wrong-peer-port", 3, 3, "target-port", ICMP_IGNORE, 0},
    {"old-sequence", 3, 3, "old-sequence", ICMP_IGNORE, 0},
    {"future-sequence", 3, 3, "future-sequence", ICMP_IGNORE, 0},
    {"half-range", 3, 3, "half-range", ICMP_IGNORE, 0},
    {"bound-device", 3, 3, "other-bound-device", ICMP_IGNORE, 0},
    {"fragmentation-needed", 3, 4, "valid", ICMP_IGNORE, 0},
    {"unknown-code", 3, 16, "valid", ICMP_IGNORE, 0},
    {"source-quench", 4, 0, "valid", ICMP_IGNORE, 0},
    {"blocking", 3, 3, "valid", ICMP_BLOCKING, 111},
    {"interrupted", 3, 3, "delayed", ICMP_INTERRUPT, 111},
    {"retained", 3, 3, "delayed", ICMP_RETAINED, 111},
    {"retry", 3, 3, "valid", ICMP_RETRY, 111},
    {"soft-port", 3, 3, "valid", ICMP_SOFT, 111},
    {"soft-ttl", 11, 0, "valid", ICMP_SOFT, 113},
    {"soft-last", 3, 3, "last-error", ICMP_SOFT, 71},
    {"soft-consumed", 3, 3, "valid", ICMP_CONSUME, 110},
    {"progress-clears", 3, 3, "valid", ICMP_RECOVER, 110},
    {"time-wait", 3, 3, "valid", ICMP_TIME_WAIT, 0},
    {"passive-port", 3, 3, "valid", ICMP_PASSIVE_KEEP, 0},
    {"passive-host", 3, 1, "valid", ICMP_PASSIVE_DROP, 0},
    {"passive-parameter", 12, 0, "valid", ICMP_PASSIVE_DROP, 0}};

#define ICMP_CASES (sizeof(icmp_cases) / sizeof(icmp_cases[0]))
#define ICMP_CYCLES 128
