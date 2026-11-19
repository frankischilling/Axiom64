// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    userspace/tests/net/manager_link_state_model.cpp
 * @brief   Network manager link state model.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Supplies controlled link state transitions for the manager test harness.
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
// Exercise the actual observer with Linux operational-state observations.
#define main manager_link_fixture_main
#include "manager-link.cpp"
#undef main

int main(int argc, char** argv) {
    check(argc == 2, "one manager link-state model case");

    struct Case {
        const char* name;
        bool administrative, running, disabled, down, up, expected;
        bool operator_up = false;
    };

    const Case cases[] = {
        {"enabled-up", true, true, false, false, true, true},
        {"enabled-not-running", true, false, false, false, true, false},
        {"disabled-up", false, false, true, false, true, true},
        {"disabled-activated", true, true, true, false, true, false},
        {"disabled-running", false, true, true, false, true, false},
        {"disabled-down", false, false, true, true, false, true},
        {"carrier-down", true, false, false, true, false, true},
        {"carrier-still-up", true, true, false, true, false, false},
        {"ordinary-observation", true, false, false, false, false, true},
        {"disabled-manual-up", true, true, true, false, true, true, true},
        {"disabled-manual-no-running", true, false, true, false, true, false, true},
        {"disabled-manual-down", true, false, true, true, false, true, true},
        {"disabled-manual-lost-admin", false, false, true, true, false, false, true}};
    for (const auto& value : cases) {
        if (strcmp(value.name, argv[1]))
            continue;
        ax::dhcp::Interface current;
        current.up = value.administrative;
        current.carrier = value.running;
        bool actual =
            link_state_matches(current, value.disabled, value.down, value.up, value.operator_up);
        printf("MANAGER_LINK_STATE_MODEL case=%s actual=%u expected=%u\n", value.name,
               unsigned(actual), unsigned(value.expected));
        return actual == value.expected ? 0 : 1;
    }
    check(false, "known manager link-state model case");
    return 1;
}
