// SPDX-License-Identifier: GPL-3.0-or-later
#define main source_route_client_main
#include "../../userspace/tests/net/ipv4/source_route_wire.c"
#undef main

int main(int argc, char** argv) {
    require(argc == 2, "regression-scenario");
    int descriptors[2];
    require(socketpair(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK, 0, descriptors) == 0,
            "regression-real-queue");
    raw_fd = descriptors[0];
    started = 1;
    observed = 0;
    guard_deadline_ns = UINT64_MAX;
    // A source-side empty proof precedes the error. Its UART acknowledgment
    // can arrive after the same client consumes that error.
    arp_seen = 3;
    guard_after_ns = 1;
    raw_seen = 1;
    if (!strcmp(argv[1], "missing-proof"))
        acknowledge_guard();
    if (!strcmp(argv[1], "early-ready"))
        require(write(descriptors[1], "E", 1) == 1, "regression-early-error");
    if (!strcmp(argv[1], "already-consumed"))
        raw_seen = 2;
    if (!strcmp(argv[1], "short-quiet"))
        guard_after_ns = UINT64_MAX;
    prove_empty_guard();
    require(guard_completed && !guard_acknowledged, "regression-retained-proof");
    require(write(descriptors[1], "E", 1) == 1, "regression-later-error");
    char error;
    require(read(descriptors[0], &error, 1) == 1 && error == 'E', "regression-consume-later-error");
    raw_seen++;
    acknowledge_guard();
    require(guard_acknowledged && !guard_deadline_ns, "regression-proof-acknowledged");
    if (!strcmp(argv[1], "duplicate-ack"))
        acknowledge_guard();
    require(close(descriptors[0]) == 0 && close(descriptors[1]) == 0, "regression-close-queue");
    return 0;
}
