// SPDX-License-Identifier: GPL-3.0-or-later
// Exercise the actual selector with a measured tentative-owner handoff.
#define main ownership_program_main
#include "ipv6_address_ownership.c"
#undef main

int main(int argc, char** argv) {
    check(argc == 2, "one ownership inventory model case");
    struct address_record old = {.flags = 0x8c0, .preferred = UINT32_MAX, .valid = UINT32_MAX};
    struct address_record fresh = old;
    check(inet_pton(AF_INET6, "fe80::c0d:e8f1:68c:e000", &old.address) == 1 &&
              inet_pton(AF_INET6, "fe80::407e:65c:1dc4:12f5", &fresh.address) == 1,
          "measured owner identities");
    struct inventory inventory = {.addresses = {old, fresh}, .address_count = 2};
    const struct in6_addr* previous = &old.address;
    unsigned count = 1, expected = 1;
    const char* kind = argv[1];
    if (!strcmp(kind, "legacy")) {
        previous = NULL;
        count = 0;
    } else if (!strcmp(kind, "context")) {
    } else if (!strcmp(kind, "reverse")) {
        inventory.addresses[0] = fresh;
        inventory.addresses[1] = old;
    } else if (!strcmp(kind, "failed-old"))
        inventory.addresses[0].flags |= IFA_F_DADFAILED;
    else if (!strcmp(kind, "old-only")) {
        inventory.address_count = 1;
        expected = 0;
    } else if (!strcmp(kind, "wrong-state")) {
        inventory.addresses[1].flags &= ~IFA_F_TENTATIVE;
        expected = 0;
    } else if (!strcmp(kind, "wrong-prefix")) {
        inventory.addresses[1].address.s6_addr[0] = 0x20;
        expected = 0;
    } else if (!strcmp(kind, "two-fresh") || !strcmp(kind, "duplicate-fresh")) {
        inventory.addresses[inventory.address_count++] = fresh;
        if (!strcmp(kind, "two-fresh"))
            inventory.addresses[2].address.s6_addr[15] ^= 1;
    } else if (!strcmp(kind, "oversized-context"))
        count = 5;
    else
        check(0, "known ownership inventory model case");
    struct address_record selected = {0};
    unsigned found = select_owner(&inventory, 1, 7, 1, 1, previous, count, &selected);
    check(found == expected, "one unconflicted tentative owner is selected");
    if (found)
        check(!memcmp(&selected.address, &fresh.address, 16) && selected.flags == 0x8c0 &&
                  selected.preferred == UINT32_MAX && selected.valid == UINT32_MAX,
              "queried fresh identity flags and lifetimes remain exact");
    puts("IPV6_OWNER_INVENTORY_PASS");
    return 0;
}
