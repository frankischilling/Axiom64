// SPDX-License-Identifier: GPL-3.0-or-later
#define DNS_CAPTURE_FRAMES 8192
#include "dns/contract.h"

static void* parallel_tcp_lookup(void* opaque) {
    unsigned index = *(unsigned*)opaque;
    char name[64];
    snprintf(name, sizeof(name), "parallel%u.tcp.fixture.", index);
    lookup("tcp-parallel", name, 0, 0x0a174101 + index, 1, NULL, 0, 900, 0);
    return NULL;
}

int main(int argc, char** argv) {
    setbuf(stdout, NULL);
    check(argc == 1 || (argc == 2 && strcmp(argv[1], "--native") == 0), "arguments");
    struct capture* captured = NULL;
    if (argc == 1) {
        configure();
        captured = calloc(1, sizeof(*captured));
        check(captured != NULL, "capture allocation");
        capture_start(captured);
    }
    printf("DNS_TCP_CONFIG_PASS linkage=%s nics=2\n", DNS_LINKAGE);
    const char* failures[] = {"wrong-id",    "wrong-name", "wrong-type",      "wrong-class",
                              "query-bit",   "opcode",     "short-prefix",    "short-body",
                              "short-frame", "refused",    "connect-refused", "compression-loop"};
    for (unsigned lane = 0; lane < 2; lane++) {
        unsigned address = 0x0a174001 + (lane << 8);
        resolver_options(lane, 0, NULL, 2);
        lookup("tcp-cold", "valid.tcp.fixture.", 0, address, 1, NULL, 0, 1900, 1);
        resolver(lane, 0, NULL);
        lookup("tcp-large", "large.tcp.fixture.", 0, address, 40, NULL, 0, 900, 1);
        lookup("tcp-split", "split.tcp.fixture.", 0, address, 40, NULL, 75, 900, 1);
        lookup("tcp-wrong-id-valid", "wrong-id-valid.tcp.fixture.", 0, address, 1, NULL, 0, 900, 1);
        lookup("tcp-casefold", "casefold.tcp.fixture.", 0, address, 1, NULL, 0, 900, 1);
        lookup("tcp-oversized", "oversized-valid.tcp.fixture.", 0, address, 40, NULL, 0, 900, 1);
        lookup("tcp-oversized-wrong-id-valid", "oversized-wrong-id-valid.tcp.fixture.", 0, address,
               1, NULL, 0, 900, 1);
        lookup("tcp-questionless-negative", "questionless-negative.tcp.fixture.", EAI_NONAME, 0, 0,
               NULL, 0, 900, 1);
        for (unsigned i = 0; i < sizeof(failures) / sizeof(failures[0]); i++) {
            char name[64];
            snprintf(name, sizeof(name), "%s.tcp.fixture.", failures[i]);
            lookup(failures[i], name, EAI_AGAIN, 0, 0, NULL, 0, 1500, 1);
        }
        lookup("tcp-silent", "silent.tcp.fixture.", EAI_AGAIN, 0, 0, NULL, 950, 1500, 1);
        printf("DNS_TCP_LANE_PASS linkage=%s lane=%u cases=21\n", DNS_LINKAGE, lane);
    }
    resolver(0, 1, NULL);
    lookup("tcp-nameserver-selection", "selection.tcp.fixture.", 0, 0x0a174101, 1, NULL, 0, 900, 1);
    resolver(1, 0, NULL);
    pthread_t threads[8];
    unsigned indices[8];
    for (unsigned i = 0; i < 8; i++) {
        indices[i] = i;
        check(pthread_create(&threads[i], NULL, parallel_tcp_lookup, &indices[i]) == 0,
              "parallel TCP creation");
    }
    for (unsigned i = 0; i < 8; i++)
        check(pthread_join(threads[i], NULL) == 0, "parallel TCP join");
    printf("DNS_TCP_PARALLEL_PASS linkage=%s threads=8\n", DNS_LINKAGE);
    int first = open("/dev/null", O_RDONLY | O_CLOEXEC);
    check(first >= 0 && close(first) == 0, "descriptor baseline");
    for (unsigned i = 0; i < 64; i++) {
        lookup("tcp-cycle-success", "cycle-success.tcp.fixture.", 0, 0x0a174141, 1, NULL, 0, 900,
               0);
        lookup("tcp-cycle-failure", "cycle-failure.tcp.fixture.", EAI_AGAIN, 0, 0, NULL, 0, 900, 0);
        int after = open("/dev/null", O_RDONLY | O_CLOEXEC);
        check(after == first && close(after) == 0, "TCP resolver descriptions reclaimed");
    }
    printf("DNS_TCP_RECLAMATION_PASS linkage=%s cycles=128\n", DNS_LINKAGE);
    if (captured) {
        capture_stop(captured);
        free(captured);
    }
    printf("DNS_TCP_TESTS_PASS linkage=%s cases=43 threads=8 cycles=128\n", DNS_LINKAGE);
    return 0;
}
