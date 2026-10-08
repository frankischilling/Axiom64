// SPDX-License-Identifier: GPL-3.0-or-later
#include "net/config/profile.hpp"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

using namespace ax::net;

static void check(bool condition, const char* message) {
    if (!condition) {
        fprintf(stderr, "DHCP_PROFILE_FAIL %s errno=%d\n", message, errno);
        exit(1);
    }
}

static const char fixed[] = "# A per-interface static override.\naxiom64-network=1\nmode=static\n"
                            "address=10.23.1.40\nnetmask=255.255.255.0\ngateway=10.23.1.1\n"
                            "dns=10.23.1.53 127.0.0.1\ndomain=lab.example.\nsearch=lab.example .\n"
                            "metric=1400\nhostname=workstation\nroute=172.20.0.0/16 10.23.1.2\n"
                            "route=192.168.4.0/24 0.0.0.0\n";

static void parsing() {
    Profile profile;
    check(parse_profile(fixed, strlen(fixed), profile) && profile.method == Method::fixed &&
              profile.address == 0x0a170128 && profile.parameters.mask == 0xffffff00 &&
              profile.parameters.router == 0x0a170101 && profile.parameters.dns_count == 2 &&
              profile.parameters.dns[1] == 0x7f000001 && profile.metric == 1400 &&
              profile.parameters.route_count == 2 &&
              profile.parameters.routes[0].destination == 0xac140000 &&
              profile.parameters.routes[0].mask == 0xffff0000 &&
              profile.parameters.routes[0].gateway == 0x0a170102 &&
              !profile.parameters.routes[1].gateway &&
              !strcmp(profile.parameters.search, "lab.example ."),
          "independent static profile fields, routes, and sanitized resolver text");
    char bytes[4096];
    size_t length = format_profile(profile, bytes, sizeof(bytes));
    check(length && strstr(bytes, "mode=static\n") && strstr(bytes, "address=10.23.1.40\n") &&
              strstr(bytes, "route=192.168.4.0/24 0.0.0.0\n"),
          "serialized profile preserves the reviewed text contract");
    Profile restored;
    check(parse_profile(bytes, length, restored) && restored.address == profile.address &&
              restored.parameters.route_count == 2 && restored.parameters.dns_count == 2 &&
              !strcmp(restored.hostname, "workstation"),
          "serialized static override remains usable by a fresh parser");
    const char* invalid[]{
        "mode=dhcp\n",
        "axiom64-network=2\nmode=dhcp\n",
        "axiom64-network=1\nmode=bogus\n",
        "axiom64-network=1\nmode=dhcp\nmode=dhcp\n",
        "axiom64-network=1\nmode=dhcp\nunknown=1\n",
        "axiom64-network=1\nmode=dhcp\naddress=10.23.1.40\n",
        "axiom64-network=1\nmode=static\naddress=10.23.1.40\n",
        "axiom64-network=1\nmode=static\naddress=10.23.1.255\nnetmask=255.255.255.0\n",
        "axiom64-network=1\nmode=static\naddress=10.23.1.0\nnetmask=255.255.255.0\n",
        "axiom64-network=1\nmode=static\naddress=10.23.1.40\nnetmask=255.0.255.0\n",
        "axiom64-network=1\nmode=static\naddress=10.23.1.40\nnetmask=255.255.255.0\ngateway=10.23."
        "2.1\n",
        "axiom64-network=1\nmode=static\naddress=10.23.1.40\nnetmask=255.255.255.0\ndns=224.0.0."
        "1\n",
        "axiom64-network=1\nmode=static\naddress=10.23.1.40\nnetmask=255.255.255.0\nsearch=bad.."
        "name\n",
        "axiom64-network=1\nmode=static\naddress=10.23.1.40\nnetmask=255.255.255.0\nsearch=abc;"
        "command\n",
        "axiom64-network=1\nmode=dhcp\nhostname=two names\n",
        "axiom64-network=1\nmode=dhcp\nmetric=1\n",
        "axiom64-network=1\nmode=dhcp\nmetric=32768\n",
        "axiom64-network=1\nmode=dhcp\nmetric=999999999999999999999999999999\n",
        "axiom64-network=1\nmode=static\naddress=10.23.1.40\nnetmask=255.255.255.0\nroute=172.20.1."
        "0/16 10.23.1.1\n",
        "axiom64-network=1\nmode=static\naddress=10.23.1.40\nnetmask=255.255.255.0\nroute=172.20.0."
        "0/33 10.23.1.1\n",
        "axiom64-network=1\nmode=static\naddress=10.23.1.40\nnetmask=255.255.255.0\nroute=172.20.0."
        "0/16 10.23.1.1\nroute=172.20.0.0/16 10.23.1.2\n"};
    for (const char* text : invalid) {
        restored.address = 0xabcdef01;
        check(!parse_profile(text, strlen(text), restored) && restored.address == 0xabcdef01,
              "malformed profile rejected without changing the caller's snapshot");
    }
    const char disabled[] = "axiom64-network=1\r\n mode = disabled \r\n";
    check(parse_profile(disabled, sizeof(disabled) - 1, restored) &&
              restored.method == Method::disabled,
          "disabled profile and CRLF whitespace");
    check(!format_profile(profile, bytes, 8), "serialization does not silently truncate");
    memset(bytes, 'x', sizeof(bytes));
    check(!parse_profile(bytes, sizeof(bytes), restored), "maximum profile text bounded");
    puts("DHCP_PROFILE_PARSING_PASS");
}

static void files(const char* root) {
    Store store(root);
    Profile original;
    check(parse_profile(fixed, strlen(fixed), original), "file fixture profile");
    check(store.write_profile("eth0", original) == 0, "checked synchronized static profile write");
    char name[320];
    check(snprintf(name, sizeof(name), "%s/eth0.conf", root) > 0, "profile path");
    int old = open(name, O_RDONLY | O_CLOEXEC);
    check(old >= 0, "retain previous profile through atomic replacement");
    Profile replacement;
    replacement.metric = 1700;
    strcpy(replacement.hostname, "changed");
    for (unsigned i = 0; i < 32; i++)
        check(store.write_profile("eth0", replacement) == 0, "repeated atomic profile replacement");
    char previous[4096];
    ssize_t count = read(old, previous, sizeof(previous) - 1);
    check(count > 0 && close(old) == 0, "old description still readable after replacement");
    previous[count] = 0;
    check(strstr(previous, "mode=static\n") && strstr(previous, "address=10.23.1.40\n"),
          "old open file retains the complete previous snapshot");
    Store fresh(root);
    Profile restored;
    check(fresh.read_profile("eth0", restored) == 0 && restored.method == Method::dhcp &&
              restored.metric == 1700 && !strcmp(restored.hostname, "changed"),
          "fresh store observes the complete replacement");
    ax::dhcp::Identity identity{{0x52, 0x54, 0, 0x12, 0x34, 0x10}, "axiom64"};
    uint32_t hint = 0;
    check(store.write_hint("eth0", identity, 0x0a170128) == 0 &&
              fresh.read_hint("eth0", identity, hint) == 0 && hint == 0x0a170128,
          "saved hint contains stable identity and address without a wall-clock deadline");
    identity.mac[5]++;
    hint = 0xabcdef01;
    check(fresh.read_hint("eth0", identity, hint) == ESTALE && hint == 0xabcdef01,
          "changed hardware identity cannot borrow a saved address");
    identity.mac[5]--;
    check(store.forget_hint("eth0") == 0 && store.forget_hint("eth0") == 0 &&
              fresh.read_hint("eth0", identity, hint) == ENOENT,
          "revoked hints removed and repeated cleanup remains safe");
    check(store.write_profile("../outside", replacement) == EINVAL &&
              store.write_hint("eth0/escape", identity, 0x0a170128) == EINVAL,
          "interface-derived names cannot escape the owned directory");
    replacement.metric = 1;
    check(store.write_profile("eth0", replacement) == EINVAL &&
              fresh.read_profile("eth0", restored) == 0 && restored.metric == 1700,
          "failed profile validation preserves the existing file");
    check(snprintf(name, sizeof(name), "%s/eth1.conf", root) > 0 && mkdir(name, 0700) == 0,
          "unreplaceable target fixture");
    check(store.write_profile("eth1", original) != 0 && rmdir(name) == 0,
          "failed rename reported and temporary file cleaned");
    check(snprintf(name, sizeof(name), "%s/eth2.conf", root) > 0 &&
              symlink("eth0.conf", name) == 0 && fresh.read_profile("eth2", restored) == ELOOP &&
              unlink(name) == 0,
          "profile reads reject a final symlink");
    check(snprintf(name, sizeof(name), "%s/eth0.conf", root) > 0 && unlink(name) == 0,
          "remove only the test's profile");
    puts("DHCP_PROFILE_ATOMIC_FILES_PASS cycles=32");
}

int main(int argc, char** argv) {
    parsing();
    char temporary[] = "/tmp/axiom64-network-XXXXXX";
    const char* directory = argc == 2 ? argv[1] : mkdtemp(temporary);
    check(directory && argc <= 2, "dedicated profile test directory");
    files(directory);
    if (argc != 2)
        check(rmdir(directory) == 0, "all owned temporary files cleaned");
    puts("DHCP_PROFILE_TESTS_PASS");
    return 0;
}
