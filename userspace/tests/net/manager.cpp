// SPDX-License-Identifier: GPL-3.0-or-later
#include "tests/net/manager-fixture.hpp"

static void profiles(Fixture& fixture) {
    ax::net::Store saved(fixture.saved);
    ax::net::Profile selected;
    bool fixed = !strcmp(fixture.scenario, "static") || !strcmp(fixture.scenario, "conflict") ||
                 !strcmp(fixture.scenario, "defense");
    if (fixed) {
        selected.method = ax::net::Method::fixed;
        selected.address = 0x0a170128;
        selected.parameters.has_mask = true;
        selected.parameters.mask = 0xffffff00;
        selected.parameters.router = 0x0a170101;
        selected.parameters.dns_count = 1;
        selected.parameters.dns[0] = 0x0a170135;
        memcpy(selected.parameters.domain, "lab.example", 12);
    } else if (!strcmp(fixture.scenario, "disabled"))
        selected.method = ax::net::Method::disabled;
    if (fixed || selected.method == ax::net::Method::disabled ||
        !strcmp(fixture.scenario, "unsafe")) {
        check(saved.write_profile(fixture.interfaces[0].name, selected) == 0,
              "validated saved override fixture");
        if (!strcmp(fixture.scenario, "unsafe")) {
            char path[300];
            snprintf(path, sizeof(path), "%s/%.15s.conf", fixture.saved,
                     fixture.interfaces[0].name);
            check(chmod(path, 0644) == 0, "unsafe saved profile mode fixture");
        }
    }
    if (!strcmp(fixture.scenario, "manual")) {
        ax::net::Routing writer;
        ax::net::Address manual{0xc0000258, 0xffffff00, 0xc00002ff, 1};
        check(writer.open() == 0 && writer.change(manual, false) == 0,
              "manual address before manager start");
    }
}

static bool persistent_scenario(const char* scenario) {
    return !strcmp(scenario, "persist-prime") || !strcmp(scenario, "persist-reboot");
}

static void persistent_before(Fixture& fixture) {
    check(!fixture.address(0) && !fixture.address(1),
          "fresh kernel begins with neither previous IPv4 address");
    fixture.routes(false, false, false);
    check(access(fixture.runtime, F_OK) < 0 && errno == ENOENT,
          "fresh boot has no previous volatile lock, marker, or ownership journal");
    check(access(fixture.resolver, F_OK) < 0 && errno == ENOENT,
          "fresh boot has no previous volatile resolver record or deadlines");
    ax::net::Store saved(fixture.saved);
    ax::net::Profile profile;
    if (!strcmp(fixture.scenario, "persist-prime")) {
        memcpy(profile.hostname, "saved-reboot", 13);
        check(saved.write_profile(fixture.interfaces[0].name, profile) == 0,
              "persistent DHCP profile is written by the production Store");
    } else {
        check(saved.read_profile(fixture.interfaces[0].name, profile) == 0 &&
                  profile.method == ax::net::Method::dhcp &&
                  !strcmp(profile.hostname, "saved-reboot"),
              "fresh boot reads the prior complete saved profile");
        for (unsigned lane = 0; lane < 2; lane++) {
            uint32_t address = 0;
            check(saved.read_hint(fixture.interfaces[lane].name, fixture.interfaces[lane].identity,
                                  address) == 0 &&
                      address == (lane ? 0x0a170228U : 0x0a170128U),
                  "fresh boot reads each private MAC/address hint without a saved deadline");
        }
    }
}

static void persistent(Fixture& fixture, uint64_t began) {
    bool reboot = !strcmp(fixture.scenario, "persist-reboot");
    while (!fixture.marker(
               "NETWORK_MANAGER_BOUND index=1 method=dhcp address=0a170128 generation=1") ||
           !fixture.marker(
               "NETWORK_MANAGER_BOUND index=2 method=dhcp address=0a170228 generation=1")) {
        check(milliseconds() < began + 60000, "both adapters validate and acquire after root boot");
        pause_ms(20);
    }
    pause_ms(2200);
    for (unsigned lane = 0; lane < 2; lane++) {
        uint32_t mask = 0;
        check(fixture.address(lane, &mask) == (lane ? 0x0a170228U : 0x0a170128U) &&
                  mask == (reboot ? 0xffffff80U : 0xffffff00U),
              "fresh ACK determines the complete tuple rather than a saved lease");
        ax::net::Store saved(fixture.saved);
        uint32_t hint = 0;
        check(saved.read_hint(fixture.interfaces[lane].name, fixture.interfaces[lane].identity,
                              hint) == 0 &&
                  hint == (lane ? 0x0a170228U : 0x0a170128U),
              "successful installation leaves a complete synchronized hint");
    }
    fixture.routes(true, true, false);
    char path[300], bytes[1024];
    snprintf(path, sizeof(path), "%s/resolv.conf", fixture.resolver);
    text(path, bytes, sizeof(bytes));
    check(strstr(bytes, reboot ? "nameserver 10.23.1.54\n" : "nameserver 10.23.1.53\n") &&
              strstr(bytes, reboot ? "nameserver 10.23.2.54\n" : "nameserver 10.23.2.53\n"),
          "fresh ACK determines both resolver contributions");
    if (!reboot) {
        snprintf(path, sizeof(path), "%s/boot-marker", fixture.runtime);
        int marker = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
        check(marker >= 0 && write(marker, "volatile\n", 9) == 9 && fsync(marker) == 0 &&
                  close(marker) == 0,
              "first boot writes a real marker under the volatile runtime mount");
        check(kill(fixture.process, SIGKILL) == 0, "terminate manager without releasing hints");
        int status = fixture.wait(fixture.process);
        fixture.evidence(fixture.primary);
        check(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL,
              "first boot reaps killed process before root shutdown");
        puts("MANAGER_PERSIST_PRIME_PASS saved=profile-and-hints runtime=volatile");
    } else {
        fixture.stop();
        check(!fixture.address(0) && !fixture.address(1),
              "fresh-boot process releases both tuples");
        fixture.routes(false, false, false);
        fixture.clean();
        puts("MANAGER_PERSIST_REBOOT_PASS hints=revalidated ack=fresh runtime=empty");
    }
    printf("MANAGER_TEST_PASS scenario=%s processes=checked resolver=merged manual=preserved\n",
           fixture.scenario);
}

static void overrides(Fixture& fixture, uint64_t began) {
    const char* scenario = fixture.scenario;
    bool fixed = !strcmp(scenario, "static") || !strcmp(scenario, "conflict") ||
                 !strcmp(scenario, "defense");
    bool first_owned = !strcmp(scenario, "static");
    bool manual = !strcmp(scenario, "manual");
    uint32_t expected = first_owned ? 0x0a170128 : manual ? 0xc0000258 : 0;
    for (;;) {
        bool ready = fixture.address(0) == expected && fixture.address(1) == 0x0a170228 &&
                     fixture.marker(
                         "NETWORK_MANAGER_BOUND index=2 method=dhcp address=0a170228 generation=1");
        if (manual)
            ready &= fixture.marker("NETWORK_MANAGER_ERROR index=1 operation=action errno=16");
        if (!strcmp(scenario, "unsafe"))
            ready &= fixture.marker("NETWORK_MANAGER_ERROR index=1 operation=profile errno=13");
        if (!strcmp(scenario, "defense"))
            ready &= fixture.marker("NETWORK_MANAGER_WITHDRAWN index=1");
        if (!strcmp(scenario, "hint-sync") || !strcmp(scenario, "resolver")) {
            char expected_error[100];
            snprintf(expected_error, sizeof(expected_error),
                     "MANAGER_FAULT_INJECT operation=%s errno=5", scenario);
            ready &= fixture.marker(expected_error) &&
                     fixture.marker("NETWORK_MANAGER_ERROR index=1 operation=action errno=5");
        }
        if (ready)
            break;
        check(milliseconds() < began + 40000,
              "independent adapter progresses with saved/manual overrides");
        pause_ms(20);
    }
    pause_ms(2200); // Require the healthy/static client's second announcement.
    check(fixture.address(0) == expected && fixture.address(1) == 0x0a170228,
          "excluded/conflicting/manual adapter does not replace its address");
    fixture.routes(first_owned, true, false, fixed);
    fixture.manual_routes();
    char path[300], bytes[1024];
    snprintf(path, sizeof(path), "%s/resolv.conf", fixture.resolver);
    text(path, bytes, sizeof(bytes));
    check((strstr(bytes, "nameserver 10.23.2.53\n") || strstr(bytes, "nameserver 10.23.2.54\n")) &&
              bool(strstr(bytes, "nameserver 10.23.1.53\n")) == first_owned &&
              !strstr(bytes, ".99\n"),
          "resolver contains only successful accepted contributions");
    fixture.stop();
    check(fixture.address(0) == (manual ? 0xc0000258 : 0) && !fixture.address(1),
          "signal withdraws owned addresses and preserves the manual address");
    fixture.routes(false, false, true, fixed);
    fixture.clean();
    fixture.manual_routes(true);
    printf("MANAGER_TEST_PASS scenario=%s processes=checked resolver=merged manual=preserved\n",
           scenario);
}

static void failed_shutdown(Fixture& fixture, uint64_t began) {
    bool retained = !strcmp(fixture.scenario, "hint-remove");
    pause_ms(2200);
    fixture.stop(true);
    check(!fixture.address(0) && !fixture.address(1),
          "failed teardown still withdraws both owned addresses");
    fixture.routes(false, false, true);
    fixture.clean(retained);
    fixture.start(false, false);
    while (!fixture.marker(
               "NETWORK_MANAGER_BOUND index=1 method=dhcp address=0a170128 generation=1") ||
           !fixture.marker(
               "NETWORK_MANAGER_BOUND index=2 method=dhcp address=0a170228 generation=1")) {
        check(milliseconds() < began + 75000,
              "normal manager restarts after a reported teardown failure");
        pause_ms(20);
    }
    pause_ms(2200);
    check(fixture.address(0) == 0x0a170128 && fixture.address(1) == 0x0a170228,
          "normal process reacquires both complete tuples");
    fixture.routes(true, true, true);
    fixture.stop();
    check(!fixture.address(0) && !fixture.address(1), "normal restart withdraws both addresses");
    fixture.routes(false, false, true);
    fixture.clean();
    fixture.manual_routes(true);
    printf("MANAGER_TEST_PASS scenario=%s processes=checked resolver=merged manual=preserved\n",
           fixture.scenario);
}

int main(int argc, char** argv) {
    alarm(110);
    check(argc == 4, "binary/scenario/root arguments");
    setvbuf(stdout, nullptr, _IOLBF, 0);
    Fixture fixture(argv[1], argv[2], argv[3]);
    check(!strcmp(argv[2], "concurrent") || !strcmp(argv[2], "missing") ||
              !strcmp(argv[2], "static") || !strcmp(argv[2], "conflict") ||
              !strcmp(argv[2], "defense") || !strcmp(argv[2], "disabled") ||
              !strcmp(argv[2], "unsafe") || !strcmp(argv[2], "manual") ||
              !strcmp(argv[2], "restart") || fault_scenario(argv[2]) ||
              persistent_scenario(argv[2]),
          "known manager scenario");
    profiles(fixture);
    if (persistent_scenario(argv[2]))
        persistent_before(fixture);
    printf("MANAGER_TEST_READY scenario=%s\n", argv[2]);
    uint64_t began = milliseconds();
    fixture.start();
    while (!fixture.marker("NETWORK_MANAGER_READY")) {
        check(milliseconds() < began + 3000, "manager startup independent of DHCP servers");
        pause_ms(20);
    }
    pid_t competing = fixture.start(true);
    int status = fixture.wait(competing);
    check(WIFEXITED(status) && WEXITSTATUS(status) == 1, "second real manager rejects singleton");
    fixture.evidence(fixture.serial);
    if (persistent_scenario(argv[2])) {
        persistent(fixture, began);
        return 0;
    }
    if (strcmp(argv[2], "concurrent") && strcmp(argv[2], "restart") &&
        strcmp(argv[2], "hint-remove") && strcmp(argv[2], "close")) {
        overrides(fixture, began);
        return 0;
    }
    while (fixture.address(0) != 0x0a170128 || fixture.address(1) != 0x0a170228 ||
           !fixture.marker(
               "NETWORK_MANAGER_BOUND index=1 method=dhcp address=0a170128 generation=1") ||
           !fixture.marker(
               "NETWORK_MANAGER_BOUND index=2 method=dhcp address=0a170228 generation=1")) {
        check(milliseconds() < began + 45000, "both clients acquire concurrently");
        pause_ms(20);
    }
    fixture.routes(true, true, false);
    fixture.manual_routes();
    if (!strcmp(argv[2], "hint-remove") || !strcmp(argv[2], "close")) {
        failed_shutdown(fixture, began);
        return 0;
    }
    if (!strcmp(argv[2], "restart")) {
        check(kill(fixture.process, SIGKILL) == 0, "abrupt actual manager death");
        status = fixture.wait(fixture.process);
        fixture.evidence(1);
        check(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL,
              "actual killed process is reaped before restart");
        check(fixture.address(0) == 0x0a170128 && fixture.address(1) == 0x0a170228,
              "killed process leaves owned state for journal recovery");
        fixture.start();
        for (;;) {
            if (fixture.marker(
                    "NETWORK_MANAGER_BOUND index=1 method=dhcp address=0a170128 generation=1") &&
                fixture.marker(
                    "NETWORK_MANAGER_BOUND index=2 method=dhcp address=0a170228 generation=1"))
                break;
            check(milliseconds() < began + 60000,
                  "new process recovers and revalidates saved hints");
            pause_ms(20);
        }
        pause_ms(2200);
        fixture.routes(true, true, true);
        fixture.stop();
        check(!fixture.address(0) && !fixture.address(1),
              "restarted process releases both addresses");
        fixture.routes(false, false, true);
        fixture.manual_routes(true);
        puts("MANAGER_TEST_PASS scenario=restart processes=checked resolver=merged "
             "manual=preserved");
        return 0;
    }
    for (;;) {
        uint32_t first, second;
        fixture.address(0, &first);
        fixture.address(1, &second);
        if (first == 0xffffff80 && second == 0xffffff80 &&
            fixture.marker(
                "NETWORK_MANAGER_BOUND index=1 method=dhcp address=0a170128 generation=2") &&
            fixture.marker(
                "NETWORK_MANAGER_BOUND index=2 method=dhcp address=0a170228 generation=2"))
            break;
        check(milliseconds() < began + 60000, "both independent clients renew and rebind");
        pause_ms(20);
    }
    fixture.routes(true, true, true);
    char path[300], bytes[1024];
    snprintf(path, sizeof(path), "%s/resolv.conf", fixture.resolver);
    text(path, bytes, sizeof(bytes));
    check(strstr(bytes, "nameserver 10.23.1.54\n") && strstr(bytes, "nameserver 10.23.2.54\n") &&
              !strstr(bytes, ".53\n") && !strstr(bytes, ".99\n"),
          "global resolver uses both accepted ACK contributions and replaces old/offer DNS");
    struct stat before;
    snprintf(path, sizeof(path), "%s/manager.lock", fixture.runtime);
    check(lstat(path, &before) == 0, "permanent lock observed while held");
    fixture.stop();
    check(!fixture.address(0) && !fixture.address(1), "signal withdraws both owned addresses");
    fixture.routes(false, false, true);
    for (const auto& interface : fixture.interfaces) {
        snprintf(path, sizeof(path), "%s/%.15s.owned", fixture.runtime, interface.name);
        check(access(path, F_OK) < 0 && errno == ENOENT, "checked ownership journal removal");
        snprintf(path, sizeof(path), "%s/%.15s.lease", fixture.saved, interface.name);
        check(access(path, F_OK) < 0 && errno == ENOENT, "release removes saved address hint");
    }
    snprintf(path, sizeof(path), "%s/resolv.conf", fixture.resolver);
    text(path, bytes, sizeof(bytes));
    check(!strstr(bytes, "nameserver "), "signal withdraws all owned resolver contributions");
    struct stat after;
    snprintf(path, sizeof(path), "%s/manager.lock", fixture.runtime);
    check(lstat(path, &after) == 0 && after.st_dev == before.st_dev &&
              after.st_ino == before.st_ino,
          "process exit preserves the permanent singleton inode");
    fixture.manual_routes(true);
    puts(
        "MANAGER_TEST_PASS scenario=concurrent processes=checked resolver=merged manual=preserved");
    return 0;
}
