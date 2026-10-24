// SPDX-License-Identifier: GPL-3.0-or-later
// Exercise the actual observer with Linux operational-state observations.
#define main manager_link_fixture_main
#include "manager-link.cpp"
#undef main

int main(int argc, char** argv) {
    check(argc == 2, "one manager link-state model case");

    struct Case {
        const char* name;
        bool administrative, running, disabled, down, up, expected;
    };

    const Case cases[] = {{"enabled-up", true, true, false, false, true, true},
                          {"enabled-not-running", true, false, false, false, true, false},
                          {"disabled-up", false, false, true, false, true, true},
                          {"disabled-activated", true, true, true, false, true, false},
                          {"disabled-running", false, true, true, false, true, false},
                          {"disabled-down", false, false, true, true, false, true},
                          {"carrier-down", true, false, false, true, false, true},
                          {"carrier-still-up", true, true, false, true, false, false},
                          {"ordinary-observation", true, false, false, false, false, true}};
    for (const auto& value : cases) {
        if (strcmp(value.name, argv[1]))
            continue;
        ax::dhcp::Interface current;
        current.up = value.administrative;
        current.carrier = value.running;
        bool actual = link_state_matches(current, value.disabled, value.down, value.up);
        printf("MANAGER_LINK_STATE_MODEL case=%s actual=%u expected=%u\n", value.name,
               unsigned(actual), unsigned(value.expected));
        return actual == value.expected ? 0 : 1;
    }
    check(false, "known manager link-state model case");
    return 1;
}
