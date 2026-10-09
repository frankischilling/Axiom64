// SPDX-License-Identifier: GPL-3.0-or-later
#include "tests/net/manager-fixture.hpp"
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <sys/socket.h>

namespace {
constexpr char manual_resolver[] = "nameserver 192.0.2.53\nsearch operator.example\n";
char manual_path[300];
ino_t manual_inode;
dev_t manual_device;

void manual_file(const Fixture& fixture, bool create = false) {
    if (create) {
        snprintf(manual_path, sizeof(manual_path), "%s%s", fixture.target,
                 !strcmp(fixture.scenario, "manual-resolver") ? "" : ".manual");
        int descriptor = open(manual_path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
        check(descriptor >= 0 &&
                  write(descriptor, manual_resolver, sizeof(manual_resolver) - 1) ==
                      ssize_t(sizeof(manual_resolver) - 1) &&
                  close(descriptor) == 0,
              "create an independent manual resolver file");
    }
    struct stat information;
    check(lstat(manual_path, &information) == 0 && S_ISREG(information.st_mode) &&
              (information.st_mode & 07777) == 0600 && information.st_uid == geteuid() &&
              information.st_nlink == 1,
          "manual resolver keeps its private regular metadata");
    if (create) {
        manual_inode = information.st_ino;
        manual_device = information.st_dev;
    }
    char bytes[256];
    check(information.st_ino == manual_inode && information.st_dev == manual_device &&
              text(manual_path, bytes, sizeof(bytes)) == sizeof(manual_resolver) - 1 &&
              !strcmp(bytes, manual_resolver),
          "manual resolver bytes and inode remain unchanged");
}

bool one_of(const char* value, const char* first, const char* second = "", const char* third = "") {
    return !strcmp(value, first) || !strcmp(value, second) || !strcmp(value, third);
}

uint64_t fingerprint(const uint8_t* bytes, size_t length) {
    uint64_t value = 14695981039346656037ULL;
    for (size_t i = 0; i < length; i++) {
        value ^= bytes[i];
        value *= 1099511628211ULL;
    }
    return value;
}

void capture_frames(const int capture[2]) {
    for (unsigned lane = 0; lane < 2; lane++) {
        for (unsigned work = 0; work < 8; work++) {
            uint8_t packet[2048];
            sockaddr_ll source{};
            socklen_t size = sizeof(source);
            ssize_t count = recvfrom(capture[lane], packet, sizeof(packet), 0,
                                     reinterpret_cast<sockaddr*>(&source), &size);
            if (count < 0 && errno == EINTR)
                continue;
            if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
                break;
            check(count >= 14 && count <= 1518 && size == sizeof(source) &&
                      source.sll_ifindex == int(lane + 1),
                  "actual driver-delivered observer frame");
            printf("MANAGER_PROTOCOL_FRAME index=%u length=%ld hash=%016llx packet_type=%u "
                   "monotonic_ms=%llu\n",
                   lane + 1, long(count), (unsigned long long)fingerprint(packet, size_t(count)),
                   unsigned(source.sll_pkttype), (unsigned long long)milliseconds());
        }
    }
}

void state(const Fixture& fixture, unsigned affected, bool owned, bool changed = false) {
    bool options = owned && !strcmp(fixture.scenario, "options");
    bool manual_target = !strcmp(fixture.scenario, "manual-resolver");
    ax::net::Routing routing;
    check(routing.open() == 0, "protocol observer route socket");
    char output[2048], path[300];
    snprintf(path, sizeof(path), "%s/resolv.conf", fixture.resolver);
    text(path, output, sizeof(output), manual_target);
    if (manual_target)
        check(!output[0] && access(path, F_OK) < 0 && errno == ENOENT,
              "manual target disables automatic resolver publication");
    manual_file(fixture);
    check(!strstr(output, ".99\n"), "rejected/OFFER resolver data is never committed");
    check(bool(strstr(output, "nameserver 1.1.1.1\n")) == options &&
              bool(strstr(output, "search lab.example dev.example\n")) == options,
          "concatenated DNS and compressed search names reach the merged resolver");
    ax::net::Store hints(fixture.saved);
    char evidence_path[340], evidence[65536];
    snprintf(evidence_path, sizeof(evidence_path), "%s.%u", fixture.log, fixture.primary);
    text(evidence_path, evidence, sizeof(evidence));
    for (unsigned lane = 0; lane < 2; lane++) {
        bool present = lane != affected || owned;
        bool fresh = lane == affected && (changed || options);
        char marker[80];
        snprintf(marker, sizeof(marker), "NETWORK_MANAGER_BOUND index=%u ", lane + 1);
        unsigned generation = 0;
        for (const char* position = evidence; (position = strstr(position, marker)); position++)
            generation++;
        bool never_bound =
            one_of(fixture.scenario, "reply-rejection", "loss-reorder", "nak-request") ||
            one_of(fixture.scenario, "nak-reboot", "conflict-probe");
        unsigned expected_generation = lane != affected ? 1
                                       : !present       ? unsigned(!never_bound)
                                       : changed && strcmp(fixture.scenario, "conflict-probe") ? 2
                                                                                               : 1;
        check(generation == expected_generation,
              "only an accepted ACK advances the actual manager lease generation");
        uint32_t mask;
        check(fixture.address(lane, &mask) == (present ? 0x0a170128U + (lane << 8) : 0) &&
                  (!present || mask == (fresh ? 0xffffff80U : 0xffffff00U)),
              "independent complete address tuple");
        ax::net::Route rows[64];
        size_t count = 0;
        check(routing.list(rows, 64, count, lane + 1) == 0, "protocol observer route dump");
        unsigned defaults = 0, classless = 0, manual = 0;
        for (size_t i = 0; i < count; i++) {
            const auto& row = rows[i];
            if (row.protocol == 16) {
                check(present && row.metric == 101 + lane, "only accepted adapter owns routes");
                if (!row.destination && !row.mask) {
                    check(row.gateway == 0x0a170101U + (lane << 8) + unsigned(fresh) &&
                              row.scope == 0,
                          "owned default route follows the accepted ACK");
                    defaults++;
                } else {
                    check(options && lane == affected && row.destination == 0xac100000 &&
                              row.mask == 0xffff0000 && !row.gateway && row.scope == 253,
                          "classless on-link route follows the accepted ACK");
                    classless++;
                }
            } else if (row.protocol == 4 && row.destination == 0xc6336400 &&
                       row.mask == 0xffffff00 && row.metric == 901 + lane)
                manual++;
        }
        check(defaults == unsigned(present) && classless == unsigned(options && lane == affected) &&
                  manual == unsigned(fixture.manual_installed[lane]),
              "complete owned/manual route counts");
        char wanted[80], stale[80];
        snprintf(wanted, sizeof(wanted), "nameserver 10.23.%u.%u\n", lane + 1, fresh ? 54 : 53);
        snprintf(stale, sizeof(stale), "nameserver 10.23.%u.%u\n", lane + 1, fresh ? 53 : 54);
        check(bool(strstr(output, wanted)) == (present && !manual_target) && !strstr(output, stale),
              "merged resolver preserves only accepted per-adapter input");
        uint32_t address = 0;
        int error = hints.read_hint(fixture.interfaces[lane].name,
                                    fixture.interfaces[lane].identity, address);
        check(present ? error == 0 && address == 0x0a170128U + (lane << 8) : error == ENOENT,
              "matching saved hints follow accepted/withdrawn ownership");
        snprintf(path, sizeof(path), "%s/%.15s.owned", fixture.runtime,
                 fixture.interfaces[lane].name);
        struct stat information;
        int result = lstat(path, &information);
        check(present ? result == 0 && S_ISREG(information.st_mode) &&
                            (information.st_mode & 07777) == 0600 &&
                            information.st_uid == geteuid() && information.st_nlink == 1
                      : result < 0 && errno == ENOENT,
              "actual private ownership journal lifetime");
        printf("MANAGER_PROTOCOL_STATE index=%u owned=%u address=%08x mask=%08x "
               "generation=%u defaults=%u classless=%u manual=%u hint=%08x\n",
               lane + 1, unsigned(present), fixture.address(lane), mask, generation, defaults,
               classless, manual, address);
    }
}

void add_manual(Fixture& fixture) {
    ax::net::Routing routing;
    check(routing.open() == 0, "manual route writer");
    for (unsigned lane = 0; lane < 2; lane++) {
        if (fixture.manual_installed[lane] || !fixture.address(lane))
            continue;
        ax::net::Route route{0xc6336400, 0xffffff00, 0, 901 + lane, lane + 1, 4, 253};
        check(routing.change(route, false) == 0, "install independent manual route");
        fixture.manual_installed[lane] = true;
    }
}
} // namespace

int main(int argc, char** argv) {
    setvbuf(stdout, nullptr, _IOLBF, 0);
    check(argc == 5, "manager binary, scenario, root and affected lane required");
    check(!strcmp(argv[4], "0") || !strcmp(argv[4], "1"), "affected real Ethernet lane");
    unsigned affected = unsigned(atoi(argv[4]));
    Fixture fixture(argv[1], argv[2], argv[3]);
    manual_file(fixture, true);
    if (!strcmp(fixture.scenario, "nak-reboot")) {
        ax::net::Store saved(fixture.saved);
        check(saved.write_hint(fixture.interfaces[affected].name,
                               fixture.interfaces[affected].identity,
                               0x0a170128U + (affected << 8)) == 0,
              "production Store prepares a matching INIT-REBOOT hint");
    }
    int capture[2];
    for (unsigned lane = 0; lane < 2; lane++) {
        capture[lane] =
            socket(AF_PACKET, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, htons(ETH_P_ALL));
        check(capture[lane] >= 0, "independent raw input observer");
        sockaddr_ll local{};
        local.sll_family = AF_PACKET;
        local.sll_ifindex = lane + 1;
        local.sll_protocol = htons(ETH_P_ALL);
        check(bind(capture[lane], reinterpret_cast<sockaddr*>(&local), sizeof(local)) == 0,
              "bind observer to actual Ethernet index");
    }
    int flags = fcntl(0, F_GETFL);
    check(flags >= 0 && fcntl(0, F_SETFL, flags | O_NONBLOCK) == 0,
          "nonblocking serial controller");
    fixture.start();
    printf("MANAGER_PROTOCOL_READY scenario=%s affected=%u pid=%d monotonic_ms=%llu\n",
           fixture.scenario, affected, fixture.process, (unsigned long long)milliseconds());
    unsigned steps = 0;
    uint64_t bound_at = 0, began = milliseconds();
    char command[64];
    size_t used = 0;
    bool finished = false;
    while (!finished) {
        check(milliseconds() - began < 170000, "bounded real protocol observation");
        check(kill(fixture.process, 0) == 0, "actual foreground manager remains alive");
        capture_frames(capture);
        for (;;) {
            char byte;
            ssize_t count = read(0, &byte, 1);
            if (count < 0 && errno == EINTR)
                continue;
            if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
                break;
            check(count == 1, "serial controller remains connected");
            if (byte == '\r')
                continue;
            if (byte != '\n') {
                check(used + 1 < sizeof(command), "bounded controller command");
                command[used++] = byte;
                continue;
            }
            command[used] = 0;
            used = 0;
            if (!strcmp(command, "snapshot") || !strcmp(command, "withdrawn")) {
                state(fixture, affected, false);
                add_manual(fixture);
                steps |= !strcmp(command, "snapshot") ? 1 : 4;
            } else if (!strcmp(command, "bound") || !strcmp(command, "recovered")) {
                if (!strcmp(command, "recovered")) {
                    char marker[120];
                    unsigned generation = !strcmp(fixture.scenario, "conflict-probe") ? 1 : 2;
                    snprintf(
                        marker, sizeof(marker),
                        "NETWORK_MANAGER_BOUND index=%u method=dhcp address=%08x generation=%u",
                        affected + 1, 0x0a170128U + (affected << 8), generation);
                    uint64_t until = milliseconds() + 5000;
                    while (!fixture.marker(marker)) {
                        check(milliseconds() < until,
                              "actual renewed generation reaches publication");
                        pause_ms(10);
                    }
                }
                state(fixture, affected, true, !strcmp(command, "recovered"));
                add_manual(fixture);
                if (!strcmp(command, "bound")) {
                    bound_at = milliseconds();
                    steps |= 2;
                } else
                    steps |= 8;
            } else if (!strcmp(command, "steady")) {
                check(bound_at && milliseconds() - bound_at >= 35000,
                      "infinite lease survives a real finite-lease observation interval");
                state(fixture, affected, true);
                steps |= 16;
            } else if (!strcmp(command, "clock")) {
                // Report the actual clock for independent backoff/expiry observations.
            } else if (!strcmp(command, "finish")) {
                check(steps & 10, "actual accepted lease observation required");
                if (one_of(fixture.scenario, "reply-rejection", "loss-reorder", "nak-request") ||
                    !strcmp(fixture.scenario, "nak-reboot"))
                    check(steps & 1, "independent rejected/revoked initial-state observation");
                if (!strcmp(fixture.scenario, "conflict-probe"))
                    check((steps & 9) == 9,
                          "unaccepted conflict and fresh acquisition observations");
                if (one_of(fixture.scenario, "nak-renew", "nak-rebind", "expiry") ||
                    one_of(fixture.scenario, "conflict-claim", "dhcp-defense"))
                    check((steps & 12) == 12, "revocation and fresh reacquisition observations");
                if (!strcmp(fixture.scenario, "infinite"))
                    check(steps & 16, "real infinite-lease interval observation");
                fixture.stop();
                capture_frames(capture);
                check(!fixture.address(0) && !fixture.address(1), "signal withdraws owned tuples");
                fixture.routes(false, false, true);
                if (strcmp(fixture.scenario, "manual-resolver"))
                    fixture.clean();
                else {
                    char path[300];
                    for (unsigned lane = 0; lane < 2; lane++) {
                        snprintf(path, sizeof(path), "%s/%.15s.owned", fixture.runtime,
                                 fixture.interfaces[lane].name);
                        check(access(path, F_OK) < 0 && errno == ENOENT,
                              "manual resolver still permits checked journal withdrawal");
                        snprintf(path, sizeof(path), "%s/%.15s.lease", fixture.saved,
                                 fixture.interfaces[lane].name);
                        check(access(path, F_OK) < 0 && errno == ENOENT,
                              "manual resolver still permits checked hint removal");
                    }
                    snprintf(path, sizeof(path), "%s/resolv.conf", fixture.resolver);
                    check(access(path, F_OK) < 0 && errno == ENOENT,
                          "manual resolver never creates an automatic output file");
                }
                manual_file(fixture);
                fixture.manual_routes(true);
                finished = true;
            } else
                check(false, "known controller command");
            printf("MANAGER_PROTOCOL_PASS stage=%s affected=%u monotonic_ms=%llu\n", command,
                   affected, (unsigned long long)milliseconds());
            if (finished)
                break;
        }
        if (!finished)
            pause_ms(10);
    }
    for (unsigned lane = 0; lane < 2; lane++) {
        uint32_t statistics[2]{};
        socklen_t size = sizeof(statistics);
        check(getsockopt(capture[lane], SOL_PACKET, PACKET_STATISTICS, statistics, &size) == 0 &&
                  size == sizeof(statistics) && statistics[0] && !statistics[1],
              "independent observer sees frames without dropping any");
        printf("MANAGER_PROTOCOL_CAPTURE index=%u packets=%u dropped=%u\n", lane + 1, statistics[0],
               statistics[1]);
    }
    for (int descriptor : capture)
        check(close(descriptor) == 0, "close independent packet observer");
    printf("MANAGER_PROTOCOL_COMPLETE scenario=%s affected=%u\n", fixture.scenario, affected);
    return 0;
}
