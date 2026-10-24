// SPDX-License-Identifier: GPL-3.0-or-later
// Exercise the actual observer with the old and replacement dump records.
#define main ipv6_dad_program_main
#include "ipv6_dad.c"
#undef main

static struct address_record record(unsigned identity, unsigned flags) {
    struct address_record result = {
        .address = prefix_address(0, 3, 0), .flags = flags, .preferred = 30, .valid = 60};
    result.address.s6_addr[15] = identity;
    return result;
}

int main(int argc, char** argv) {
    check(argc == 2, "one inventory model case");
    struct address_record old = record(1, 0x940), fresh = record(2, 0x940);
    struct in6_addr previous = old.address;
    struct inventory inventory = {0};
    struct address_record value = {0};
    int expected = 1, final_count = 0;
    const char* kind = argv[1];
    if (!strcmp(kind, "fresh"))
        inventory.addresses[inventory.address_count++] = fresh;
    else if (!strcmp(kind, "failed-first") || !strcmp(kind, "failed-last") ||
             !strcmp(kind, "tentative-first") || !strcmp(kind, "tentative-last") ||
             !strcmp(kind, "final-count")) {
        if (!strncmp(kind, "failed", 6))
            old.flags |= IFA_F_DADFAILED;
        int reverse = strstr(kind, "last") != NULL;
        inventory.addresses[inventory.address_count++] = reverse ? fresh : old;
        inventory.addresses[inventory.address_count++] = reverse ? old : fresh;
        final_count = !strcmp(kind, "final-count");
    } else if (!strcmp(kind, "previous")) {
        inventory.addresses[inventory.address_count++] = old;
        expected = 0;
    } else if (!strcmp(kind, "failed")) {
        fresh.flags |= IFA_F_DADFAILED;
        inventory.addresses[inventory.address_count++] = fresh;
        expected = 0;
    } else if (!strcmp(kind, "unrelated") || !strcmp(kind, "unrelated-and-fresh")) {
        old.address.s6_addr[7] = 4;
        inventory.addresses[inventory.address_count++] = old;
        expected = !strcmp(kind, "unrelated-and-fresh");
        if (expected)
            inventory.addresses[inventory.address_count++] = fresh;
    } else if (!strcmp(kind, "absent"))
        expected = 0;
    else if (!strcmp(kind, "two-fresh") || !strcmp(kind, "duplicate-fresh")) {
        inventory.addresses[inventory.address_count++] = fresh;
        inventory.addresses[inventory.address_count++] = fresh;
        if (!strcmp(kind, "two-fresh"))
            inventory.addresses[1].address.s6_addr[15] = 3;
    } else if (!strcmp(kind, "three-owners")) {
        inventory.addresses[inventory.address_count++] = old;
        inventory.addresses[inventory.address_count++] = fresh;
        fresh.flags |= IFA_F_DADFAILED;
        fresh.address.s6_addr[15] = 3;
        inventory.addresses[inventory.address_count++] = fresh;
    } else
        check(0, "known inventory model case");
    if (final_count)
        check(selected(&inventory, 0, 3, &value) == 2,
              "final uniqueness sees both actual owners during a handoff");
    else {
        int found = candidate(&inventory, 0, 3, &previous, &value);
        check(found == expected, "only a new nonfailed candidate is selected");
        if (found)
            check(!memcmp(&value.address, &fresh.address, 16) && value.flags == 0x940 &&
                      value.preferred == 30 && value.valid == 60,
                  "new candidate identity flags and lifetimes stay exact");
    }
    puts("IPV6_DAD_INVENTORY_PASS");
    return 0;
}
