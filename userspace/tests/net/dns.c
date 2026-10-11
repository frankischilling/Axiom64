// SPDX-License-Identifier: GPL-3.0-or-later
#include "dns/contract.h"

static void* parallel_lookup(void* opaque) {
    unsigned index = *(unsigned*)opaque;
    char name[64];
    snprintf(name, sizeof(name), "parallel%u.linux-abi.fixture.", index);
    lookup("parallel", name, 0, 0x0a174001 + index, 1, NULL, 0, 900, 0);
    return NULL;
}

int main(int argc, char** argv) {
    setbuf(stdout, NULL);
    check(argc == 1 || (argc == 2 && strcmp(argv[1], "--native") == 0), "arguments");
    if (argc == 1)
        configure();
    struct capture captured = {0};
    if (argc == 1)
        capture_start(&captured);
    resolver(0, 0, NULL);
    lookup("numeric", "10.23.1.99", 0, 0x0a170163, 1, "10.23.1.99", 0, 900, 1);
    lookup("hosts", "local-host.fixture", 0, 0x0a170164, 1, "local-host.fixture", 0, 900, 1);
    for (unsigned lane = 0; lane < 2; lane++) {
        /* Include cold link/ARP setup within a bounded two-second first lookup. */
        resolver_options(lane, 0, NULL, 2);
        char label[32];
        snprintf(label, sizeof(label), "wire-lane%u", lane);
        lookup(label, "wire.linux-abi.fixture.", 0, 0x0a173001 + lane, 1, "wire.linux-abi.fixture",
               0, 1900, 1);
    }
    resolver(0, 0, NULL);
    lookup("cname", "alias.linux-abi.fixture.", 0, 0x0a173010, 2, "canonical.linux-abi.fixture", 0,
           900, 1);
    resolver(0, 0, "missing.fixture linux-abi.fixture");
    lookup("search", "short", 0, 0x0a173020, 1, "short.linux-abi.fixture", 0, 900, 1);
    lookup("search-bare", "bare", 0, 0x0a173021, 1, "bare", 0, 900, 1);
    lookup("absolute", "absolute.", 0, 0x0a173022, 1, "absolute", 0, 900, 1);
    lookup("ndots", "dot.name", 0, 0x0a173023, 1, "dot.name.linux-abi.fixture", 0, 900, 1);
    resolver(0, 0, NULL);
    lookup("nxdomain", "absent.linux-abi.fixture.", EAI_NONAME, 0, 0, NULL, 0, 900, 1);
    lookup("nodata", "empty.linux-abi.fixture.", EAI_NODATA, 0, 0, NULL, 0, 900, 1);
    lookup("reply-filter", "filtered.linux-abi.fixture.", 0, 0x0a173030, 1, NULL, 90, 900, 1);
    lookup("retry", "retry.linux-abi.fixture.", 0, 0x0a173031, 1, NULL, 450, 900, 1);
    lookup("timeout", "timeout.linux-abi.fixture.", EAI_AGAIN, 0, 0, NULL, 950, 1500, 1);
    lookup("refused", "refused.linux-abi.fixture.", EAI_AGAIN, 0, 0, NULL, 950, 1500, 1);
    lookup("servfail", "servfail.linux-abi.fixture.", EAI_AGAIN, 0, 0, NULL, 950, 1500, 1);
    resolver(0, 1, NULL);
    lookup("parallel-nameservers", "failover.linux-abi.fixture.", 0, 0x0a173032, 1, NULL, 0, 900,
           1);
    resolver(1, 0, NULL);
    pthread_t threads[8];
    unsigned indices[8];
    for (unsigned i = 0; i < 8; i++) {
        indices[i] = i;
        check(pthread_create(&threads[i], NULL, parallel_lookup, &indices[i]) == 0,
              "parallel creation");
    }
    for (unsigned i = 0; i < 8; i++)
        check(pthread_join(threads[i], NULL) == 0, "parallel join");
    printf("DNS_PARALLEL_PASS linkage=%s threads=8\n", DNS_LINKAGE);
    int first = open("/dev/null", O_RDONLY | O_CLOEXEC);
    check(first >= 0 && close(first) == 0, "descriptor baseline");
    for (unsigned i = 0; i < 128; i++)
        lookup("reclamation", "cycles.linux-abi.fixture.", 0, 0x0a173033, 1, NULL, 0, 900, 0);
    int after = open("/dev/null", O_RDONLY | O_CLOEXEC);
    check(after == first && close(after) == 0, "resolver descriptions reclaimed");
    printf("DNS_RECLAMATION_PASS linkage=%s cycles=128\n", DNS_LINKAGE);
    if (argc == 1)
        capture_stop(&captured);
    printf("DNS_TESTS_PASS linkage=%s cases=17 threads=8 cycles=128\n", DNS_LINKAGE);
    return 0;
}
