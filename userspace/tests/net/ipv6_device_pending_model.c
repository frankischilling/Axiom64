// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    userspace/tests/net/ipv6_device_pending_model.c
 * @brief   IPv6 pending device model.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Supplies modeled results used to test pending-operation evidence handling.
 *
 * Copyright (C) 2026 frankischilling
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://gnu.org/licenses/>.
 */
#define main ipv6_pending_client_main
#include "ipv6_device_pending.c"
#undef main

int main(int argc, char** argv) {
    check(argc == 2, "explicit first-ready model case");
    action = 2;
    state = REGENERATING;
    struct inventory values = {.address_count = 2};
    struct address_record* failed = values.addresses;
    struct address_record* ready = values.addresses + 1;
    check(inet_pton(AF_INET6, "fe80::1", &failed->address) == 1 &&
              inet_pton(AF_INET6, "fe80::2", &ready->address) == 1,
          "model owner addresses");
    failed->flags = 0x8c8;
    failed->preferred = failed->valid = UINT32_MAX;
    ready->flags = 0x880;
    ready->preferred = ready->valid = UINT32_MAX;
    conflicted[conflict_count++] = failed->address;

    int expected = 1;
    if (!strcmp(argv[1], "tentative")) {
        ready->flags = 0x8c0;
        expected = 0;
    } else if (!strcmp(argv[1], "exhausted")) {
        state = EXHAUSTED;
        ready->flags = 0x8c8;
        expected = 0;
    } else if (!strcmp(argv[1], "administrative") || !strcmp(argv[1], "mtu")) {
        action = !strcmp(argv[1], "mtu");
        expected = 0;
    } else if (!strcmp(argv[1], "already-recorded")) {
        unavailable_ready_recorded = 1;
        expected = 0;
    } else if (!strcmp(argv[1], "invalid-flags")) {
        ready->flags = 0x800;
    } else if (!strcmp(argv[1], "finite-lifetime")) {
        ready->valid = 30;
    } else {
        check(!strcmp(argv[1], "first-inventory-ready"), "known first-ready model case");
    }

    struct address_record observed = {0};
    check(first_unavailable_ready(&values, &observed) == expected,
          "first inventory and poll select the same ready owner");
    if (expected) {
        check(unavailable_ready_recorded && !memcmp(&observed, ready, sizeof(observed)),
              "first actual ready owner is retained");
        check(!first_unavailable_ready(&values, &observed),
              "later poll cannot repeat the first ready record");
    }
    if (!strcmp(argv[1], "tentative")) {
        check(!unavailable_ready_recorded, "tentative query does not consume the ready record");
        ready->flags = 0x880;
        check(first_unavailable_ready(&values, &observed) && unavailable_ready_recorded,
              "first later ready query is recorded");
    }
    puts("IPV6_DEVICE_FIRST_READY_MODEL_PASS");
    return 0;
}
