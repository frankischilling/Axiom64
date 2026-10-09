// SPDX-License-Identifier: GPL-3.0-or-later
#include "tests/net/manager-fixture.hpp"
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <sys/socket.h>

namespace {
constexpr char manual_resolver[] = "nameserver 192.0.2.53\nsearch operator.example\n";

struct Observer {
    Fixture fixture;
    unsigned affected;
    bool fixed, disabled, failed, before_bound, foreign_address = false;
    int capture[2];
    bool capture_failed[2]{};
    char profile_bytes[2][2048], manual_path[300];
    struct stat profiles[2]{}, manual{};

    Observer(const char* binary, const char* scenario, const char* root, unsigned lane)
        : fixture(binary, scenario, root), affected(lane), fixed(!strncmp(scenario, "static-", 7)),
          disabled(!strncmp(scenario, "disabled", 8)),
          failed(!strncmp(scenario, "failed-", 7) || !strcmp(scenario, "static-failed") ||
                 !strcmp(scenario, "manual-failed") || !strcmp(scenario, "disabled-failed")),
          before_bound(strstr(scenario, "initial") || strstr(scenario, "selecting") ||
                       strstr(scenario, "probing") || !strcmp(scenario, "rx-length")) {
        ax::net::Store saved(fixture.saved);
        for (unsigned index = 0; index < 2; index++) {
            ax::net::Profile profile;
            memcpy(profile.hostname, "manager-link", 13);
            if (index == affected && fixed) {
                profile.method = ax::net::Method::fixed;
                profile.address = 0x0a170128U + (index << 8);
                profile.parameters.has_mask = true;
                profile.parameters.mask = 0xffffff00;
                profile.parameters.router = 0x0a170101U + (index << 8);
                profile.parameters.dns_count = 1;
                profile.parameters.dns[0] = 0x0a170135U + (index << 8);
                memcpy(profile.parameters.domain, "lab.example", 12);
            } else if (index == affected && disabled)
                profile.method = ax::net::Method::disabled;
            check(saved.write_profile(fixture.interfaces[index].name, profile) == 0,
                  "actual Store writes each private saved profile");
            char path[300];
            snprintf(path, sizeof(path), "%s/%.15s.conf", fixture.saved,
                     fixture.interfaces[index].name);
            text(path, profile_bytes[index], sizeof(profile_bytes[index]));
            check(lstat(path, &profiles[index]) == 0, "record actual saved profile metadata");
            capture[index] =
                socket(AF_PACKET, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, htons(ETH_P_ALL));
            check(capture[index] >= 0, "independent raw driver observer");
            sockaddr_ll local{};
            local.sll_family = AF_PACKET;
            local.sll_ifindex = index + 1;
            local.sll_protocol = htons(ETH_P_ALL);
            check(bind(capture[index], reinterpret_cast<sockaddr*>(&local), sizeof(local)) == 0,
                  "bind actual interface packet observer");
        }
        snprintf(manual_path, sizeof(manual_path), "%s.manual", fixture.target);
        int fd = open(manual_path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
        check(fd >= 0 &&
                  write(fd, manual_resolver, sizeof(manual_resolver) - 1) ==
                      ssize_t(sizeof(manual_resolver) - 1) &&
                  close(fd) == 0 && lstat(manual_path, &manual) == 0,
              "independent private manual resolver file");
        manual_routes();
    }

    void frames() {
        for (unsigned lane = 0; lane < 2; lane++) {
            if (capture_failed[lane])
                continue;
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
                if (count < 0 && errno == EIO) {
                    check(failed && lane == affected, "only selected failed driver reports EIO");
                    capture_failed[lane] = true;
                    printf("MANAGER_LINK_DRIVER_FAILED index=%u errno=%d monotonic_ms=%llu\n",
                           lane + 1, EIO, (unsigned long long)milliseconds());
                    break;
                }
                check(count >= 14 && count <= 1518 && size == sizeof(source) &&
                          source.sll_ifindex == int(lane + 1),
                      "actual driver-delivered packet");
                uint64_t hash = 14695981039346656037ULL;
                for (ssize_t at = 0; at < count; at++) {
                    hash ^= packet[at];
                    hash *= 1099511628211ULL;
                }
                printf("MANAGER_LINK_FRAME index=%u length=%ld hash=%016llx packet_type=%u "
                       "monotonic_ms=%llu\n",
                       lane + 1, long(count), (unsigned long long)hash,
                       unsigned(source.sll_pkttype), (unsigned long long)milliseconds());
            }
        }
    }

    unsigned generation(unsigned lane) const {
        char path[340], bytes[65536], marker[80];
        snprintf(path, sizeof(path), "%s.%u", fixture.log, fixture.primary);
        text(path, bytes, sizeof(bytes));
        snprintf(marker, sizeof(marker), "NETWORK_MANAGER_BOUND index=%u ", lane + 1);
        unsigned result = 0;
        for (const char* at = bytes; (at = strstr(at, marker)); at++)
            result++;
        return result;
    }

    void carrier_observation(bool up, unsigned required) {
        char path[340], bytes[65536], marker[100];
        snprintf(path, sizeof(path), "%s.%u", fixture.log, fixture.primary);
        snprintf(marker, sizeof(marker), "NETWORK_MANAGER_LINK index=%u up=%u\n", affected + 1,
                 unsigned(up));
        uint64_t until = milliseconds() + 5000;
        unsigned count;
        for (;;) {
            text(path, bytes, sizeof(bytes));
            count = 0;
            for (const char* at = bytes; (at = strstr(at, marker)); at++)
                count++;
            if (count >= required)
                break;
            check(milliseconds() < until, "actual manager observed each physical carrier event");
            frames();
            pause_ms(10);
        }
        printf("MANAGER_LINK_CARRIER index=%u up=%u observations=%u monotonic_ms=%llu\n",
               affected + 1, unsigned(up), count, (unsigned long long)milliseconds());
    }

    void failure_observation() {
        char path[340], bytes[65536], marker[100];
        snprintf(path, sizeof(path), "%s.%u", fixture.log, fixture.primary);
        snprintf(marker, sizeof(marker), "NETWORK_MANAGER_ERROR index=%u operation=", affected + 1);
        uint64_t until = milliseconds() + 5000;
        for (;;) {
            text(path, bytes, sizeof(bytes));
            bool found = false;
            for (const char* at = bytes; (at = strstr(at, marker)); at++) {
                const char* end = strchr(at, '\n');
                const char* error = strstr(at, " errno=5\n");
                if (end && error && error < end)
                    found = true;
            }
            if (found)
                break;
            check(milliseconds() < until, "actual manager observes permanent driver EIO");
            frames();
            pause_ms(10);
        }
        printf("MANAGER_LINK_MANAGER_FAILED index=%u errno=5 monotonic_ms=%llu\n", affected + 1,
               (unsigned long long)milliseconds());
    }

    void manual_routes() {
        ax::net::Routing writer;
        check(writer.open() == 0, "independent manual route writer");
        for (unsigned lane = 0; lane < 2; lane++) {
            if (fixture.manual_installed[lane])
                continue;
            ax::net::Route route{0xc6336400, 0xffffff00, 0, 901 + lane, lane + 1, 4, 253};
            int error = writer.change(route, false);
            printf("MANAGER_LINK_MANUAL_ROUTE index=%u error=%d\n", lane + 1, error);
            check(error == 0, "add each manual route only once");
            fixture.manual_installed[lane] = true;
        }
    }

    void files() const {
        char path[300], bytes[2048];
        struct stat information;
        for (unsigned lane = 0; lane < 2; lane++) {
            snprintf(path, sizeof(path), "%s/%.15s.conf", fixture.saved,
                     fixture.interfaces[lane].name);
            text(path, bytes, sizeof(bytes));
            check(lstat(path, &information) == 0 && S_ISREG(information.st_mode) &&
                      (information.st_mode & 07777) == 0600 && information.st_uid == geteuid() &&
                      information.st_gid == getegid() && information.st_nlink == 1 &&
                      information.st_ino == profiles[lane].st_ino &&
                      information.st_dev == profiles[lane].st_dev &&
                      !strcmp(bytes, profile_bytes[lane]),
                  "profile bytes, inode and private metadata stay unchanged");
        }
        text(manual_path, bytes, sizeof(bytes));
        check(lstat(manual_path, &information) == 0 && S_ISREG(information.st_mode) &&
                  (information.st_mode & 07777) == 0600 && information.st_uid == geteuid() &&
                  information.st_gid == manual.st_gid && information.st_nlink == 1 &&
                  information.st_ino == manual.st_ino && information.st_dev == manual.st_dev &&
                  !strcmp(bytes, manual_resolver),
              "manual resolver bytes, inode and private metadata stay unchanged");
    }

    bool withdrawn() const {
        char path[300], resolver[2048], contribution[80];
        snprintf(path, sizeof(path), "%s/%.15s.owned", fixture.runtime,
                 fixture.interfaces[affected].name);
        if (access(path, F_OK) == 0)
            return false;
        check(errno == ENOENT, "actual ownership journal lookup");
        ax::net::Routing routes;
        ax::net::Route rows[64];
        size_t count = 0;
        check(routes.open() == 0 && routes.list(rows, 64, count, affected + 1) == 0,
              "actual withdrawal route dump");
        for (size_t index = 0; index < count; index++)
            if (rows[index].metric == 101 + affected)
                return false;
        snprintf(path, sizeof(path), "%s/resolv.conf", fixture.resolver);
        text(path, resolver, sizeof(resolver));
        snprintf(contribution, sizeof(contribution), "nameserver 10.23.%u.", affected + 1);
        return !strstr(resolver, contribution);
    }

    void wait_state(bool owned, unsigned healthy_generation, unsigned target_generation,
                    bool down = false, bool up = false) {
        uint64_t until = milliseconds() + 5000;
        for (;;) {
            ax::dhcp::Interface current;
            check(ax::dhcp::query_interface(affected + 1, current) == 0,
                  "query actual selected driver flags");
            bool correct_address =
                fixture.address(affected) == (foreign_address ? 0xc0000258U + affected
                                              : owned         ? 0x0a170128U + (affected << 8)
                                                              : 0);
            if (correct_address && generation(1 - affected) == healthy_generation &&
                generation(affected) == target_generation && (!down || !current.carrier) &&
                (!up || current.carrier) && (owned || withdrawn()))
                break;
            check(milliseconds() < until, "bounded actual ownership/generation transition");
            frames();
            pause_ms(10);
        }
    }

    void state(bool owned, unsigned healthy_generation, unsigned target_generation,
               bool changed = false, bool retained_hint = false) {
        files();
        char path[300], resolver[2048];
        snprintf(path, sizeof(path), "%s/resolv.conf", fixture.resolver);
        text(path, resolver, sizeof(resolver));
        ax::net::Routing routes;
        check(routes.open() == 0, "actual route observer");
        ax::net::Store saved(fixture.saved);
        for (unsigned lane = 0; lane < 2; lane++) {
            bool target = lane == affected, present = !target || owned;
            uint32_t address, mask;
            address = fixture.address(lane, &mask);
            uint32_t wanted = target && foreign_address ? 0xc0000258U + affected
                              : present                 ? 0x0a170128U + (lane << 8)
                                                        : 0;
            check(address == wanted &&
                      mask == (!wanted                                           ? 0
                               : changed && target && !fixed && !foreign_address ? 0xffffff80U
                                                                                 : 0xffffff00U),
                  "complete owned or independent manual address tuple");
            unsigned gen = generation(lane);
            check(gen == (target ? target_generation : healthy_generation),
                  "actual manager generation follows accepted installation only");
            ax::net::Route rows[64];
            size_t count = 0;
            check(routes.list(rows, 64, count, lane + 1) == 0, "actual complete route dump");
            unsigned defaults = 0, manuals = 0;
            for (size_t index = 0; index < count; index++) {
                const auto& row = rows[index];
                if (row.metric == 101 + lane && row.protocol == (target && fixed ? 4 : 16)) {
                    check(present && !row.destination && !row.mask && row.scope == 0 &&
                              row.gateway ==
                                  0x0a170101U + (lane << 8) + unsigned(changed && target && !fixed),
                          "owned default route reflects the committed configuration");
                    defaults++;
                }
                if (row.protocol == 4 && row.metric == 901 + lane &&
                    row.destination == 0xc6336400 && row.mask == 0xffffff00 && !row.gateway &&
                    row.scope == 253)
                    manuals++;
            }
            check(defaults == unsigned(present) &&
                      manuals == unsigned(fixture.manual_installed[lane]),
                  "owned withdrawal preserves every independent manual route");
            char wanted_dns[80], stale_dns[80];
            unsigned dns = changed && target && !fixed ? 54 : 53;
            snprintf(wanted_dns, sizeof(wanted_dns), "nameserver 10.23.%u.%u\n", lane + 1, dns);
            snprintf(stale_dns, sizeof(stale_dns), "nameserver 10.23.%u.%u\n", lane + 1,
                     dns == 53 ? 54 : 53);
            check(bool(strstr(resolver, wanted_dns)) == present && !strstr(resolver, stale_dns),
                  "resolver contributions follow actual per-adapter ownership");
            uint32_t hint = 0;
            int error = saved.read_hint(fixture.interfaces[lane].name,
                                        fixture.interfaces[lane].identity, hint);
            bool has_hint =
                (present || (target && retained_hint)) && !(target && (fixed || disabled));
            check(has_hint ? !error && hint == 0x0a170128U + (lane << 8) : error == ENOENT,
                  "saved hints follow accepted lease and carrier/failure retention policy");
            snprintf(path, sizeof(path), "%s/%.15s.owned", fixture.runtime,
                     fixture.interfaces[lane].name);
            struct stat information;
            int found = lstat(path, &information);
            check(present ? found == 0 && S_ISREG(information.st_mode) &&
                                (information.st_mode & 07777) == 0600 &&
                                information.st_uid == geteuid() && information.st_nlink == 1
                          : found < 0 && errno == ENOENT,
                  "actual private ownership journal follows committed state");
            ax::dhcp::Interface interface;
            check(ax::dhcp::query_interface(lane + 1, interface) == 0,
                  "independent actual carrier/administrator state");
            printf("MANAGER_LINK_STATE index=%u owned=%u address=%08x mask=%08x generation=%u "
                   "defaults=%u manual=%u hint=%08x carrier=%u administrative=%u\n",
                   lane + 1, unsigned(present), address, mask, gen, defaults, manuals, hint,
                   unsigned(interface.carrier), unsigned(interface.up));
        }
    }
};
} // namespace

int main(int argc, char** argv) {
    setvbuf(stdout, nullptr, _IOLBF, 0);
    check(argc == 5 && (!strcmp(argv[4], "0") || !strcmp(argv[4], "1")),
          "manager binary, scenario, fixture root and selected real Ethernet lane");
    Observer observer(argv[1], argv[2], argv[3], unsigned(atoi(argv[4])));
    auto& fixture = observer.fixture;
    int flags = fcntl(0, F_GETFL);
    check(flags >= 0 && fcntl(0, F_SETFL, flags | O_NONBLOCK) == 0,
          "nonblocking serial stage controller");
    fixture.start();
    printf("MANAGER_LINK_READY scenario=%s affected=%u pid=%d monotonic_ms=%llu\n", argv[2],
           observer.affected, fixture.process, (unsigned long long)milliseconds());
    char command[64];
    size_t used = 0;
    unsigned phases = 0;
    unsigned down_observations = 0;
    bool finished = false;
    uint64_t began = milliseconds();
    while (!finished) {
        check(milliseconds() - began < 180000 && kill(fixture.process, 0) == 0,
              "bounded actual foreground manager observation");
        observer.frames();
        for (;;) {
            char byte;
            ssize_t size = read(0, &byte, 1);
            if (size < 0 && errno == EINTR)
                continue;
            if (size < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
                break;
            check(size == 1, "serial controller stays connected");
            if (byte == '\r')
                continue;
            if (byte != '\n') {
                check(used + 1 < sizeof(command), "bounded serial command");
                command[used++] = byte;
                continue;
            }
            command[used] = 0;
            used = 0;
            bool initially_owned = !observer.before_bound && !observer.disabled;
            unsigned old_generation = unsigned(initially_owned);
            bool retained = initially_owned && !observer.fixed;
            if (!strcmp(command, "initial")) {
                observer.wait_state(initially_owned, 1, old_generation);
                observer.state(initially_owned, 1, old_generation);
                observer.manual_routes();
                phases |= 1;
            } else if (!strcmp(command, "manual")) {
                check(initially_owned && (phases & 1),
                      "accepted address precedes manual replacement");
                ax::net::Routing writer;
                ax::net::Address old{0x0a170128U + (observer.affected << 8), 0xffffff00,
                                     0x0a1701ffU + (observer.affected << 8), observer.affected + 1};
                ax::net::Address foreign{0xc0000258U + observer.affected, 0xffffff00, 0xc00002ff,
                                         observer.affected + 1};
                check(writer.open() == 0 && writer.change(old, true) == 0 &&
                          writer.change(foreign, false) == 0,
                      "independent operator replaces owned address through actual netlink");
                observer.foreign_address = true;
                check(fixture.address(observer.affected) == foreign.address,
                      "actual independent manual address installed");
                phases |= 16;
            } else if (!strcmp(command, "down") || !strcmp(command, "progress") ||
                       !strcmp(command, "flap")) {
                unsigned healthy_generation = !strcmp(command, "down") ? 1 : 2;
                if (observer.failed && !observer.disabled && !strcmp(command, "down"))
                    observer.failure_observation();
                if ((!strcmp(command, "down") || !strcmp(command, "flap")) && !observer.failed &&
                    !observer.disabled && !strstr(argv[2], "initial") &&
                    strcmp(argv[2], "rx-length"))
                    observer.carrier_observation(false, ++down_observations);
                observer.wait_state(false, healthy_generation, old_generation,
                                    strcmp(argv[2], "rx-length") != 0);
                observer.state(false, healthy_generation, old_generation, false, retained);
                check(!observer.failed || observer.capture_failed[observer.affected],
                      "actual removed driver reports permanent EIO");
                if (!strcmp(command, "down"))
                    phases |= 2;
                else if (!strcmp(command, "progress"))
                    phases |= 4;
            } else if (!strcmp(command, "revalidating")) {
                check(!observer.failed && !observer.disabled,
                      "only a returned usable adapter revalidates");
                if (strcmp(argv[2], "rx-length"))
                    observer.carrier_observation(
                        true, down_observations + unsigned(strstr(argv[2], "initial") != nullptr));
                observer.wait_state(false, 2, old_generation, false, true);
                observer.state(false, 2, old_generation, false, retained);
            } else if (!strcmp(command, "recovered")) {
                check(!observer.failed && !observer.disabled && !observer.foreign_address,
                      "only a returned usable adapter reacquires ownership");
                if (strcmp(argv[2], "rx-length"))
                    observer.carrier_observation(
                        true, down_observations + unsigned(strstr(argv[2], "initial") != nullptr));
                observer.wait_state(true, 2, old_generation + 1, false, true);
                observer.state(true, 2, old_generation + 1, initially_owned);
                observer.manual_routes();
                phases |= 8;
            } else if (!strcmp(command, "up")) {
                check(observer.disabled || observer.foreign_address,
                      "saved-disabled or manual adapter stays unowned after carrier return");
                if (!observer.disabled)
                    observer.carrier_observation(true, down_observations);
                if (observer.foreign_address) {
                    char path[340], bytes[65536], marker[100];
                    snprintf(path, sizeof(path), "%s.%u", fixture.log, fixture.primary);
                    snprintf(marker, sizeof(marker),
                             "NETWORK_MANAGER_ERROR index=%u operation=action errno=%d",
                             observer.affected + 1, EBUSY);
                    uint64_t until = milliseconds() + 5000;
                    for (;;) {
                        text(path, bytes, sizeof(bytes));
                        if (strstr(bytes, marker))
                            break;
                        check(milliseconds() < until,
                              "actual install refuses independent manual address");
                        observer.frames();
                        pause_ms(10);
                    }
                }
                observer.wait_state(false, 2, old_generation, false, true);
                observer.state(false, 2, old_generation);
                phases |= 8;
            } else if (!strcmp(command, "finish")) {
                check((phases & 7) == 7 && (observer.failed || (phases & 8)),
                      "initial/withdrawn/healthy-renewal/return observations all required");
                if (!strncmp(argv[2], "manual-", 7))
                    check(phases & 16, "actual independent manual address observation required");
                fixture.stop();
                observer.frames();
                observer.files();
                check(fixture.address(1 - observer.affected) == 0 &&
                          fixture.address(observer.affected) ==
                              (observer.foreign_address ? 0xc0000258U + observer.affected : 0),
                      "checked signal teardown preserves only independent manual addresses");
                ax::net::Routing routes;
                check(routes.open() == 0, "final route observer");
                for (unsigned lane = 0; lane < 2; lane++) {
                    ax::net::Route rows[64];
                    size_t count = 0;
                    check(routes.list(rows, 64, count, lane + 1) == 0, "final actual route dump");
                    for (size_t at = 0; at < count; at++)
                        check(rows[at].metric != 101 + lane,
                              "signal removes owned DHCP/static routes on both adapters");
                    char path[300];
                    snprintf(path, sizeof(path), "%s/%.15s.owned", fixture.runtime,
                             fixture.interfaces[lane].name);
                    check(access(path, F_OK) < 0 && errno == ENOENT,
                          "checked signal removes each private ownership journal");
                    ax::net::Store saved(fixture.saved);
                    uint32_t hint = 0;
                    int error = saved.read_hint(fixture.interfaces[lane].name,
                                                fixture.interfaces[lane].identity, hint);
                    bool keep = lane == observer.affected && observer.failed && retained;
                    check(keep ? !error && hint == 0x0a170128U + (lane << 8) : error == ENOENT,
                          "only an interrupted accepted lease retains a reboot-validation hint");
                    uint32_t final_mask;
                    uint32_t final_address = fixture.address(lane, &final_mask);
                    unsigned manuals = 0;
                    for (size_t at = 0; at < count; at++)
                        manuals += rows[at].metric == 901 + lane && rows[at].protocol == 4 &&
                                   rows[at].destination == 0xc6336400 &&
                                   rows[at].mask == 0xffffff00 && !rows[at].gateway &&
                                   rows[at].scope == 253;
                    check(manuals == unsigned(fixture.manual_installed[lane]),
                          "final complete route dump preserves independent manual routes");
                    printf("MANAGER_LINK_FINAL index=%u address=%08x mask=%08x hint=%08x "
                           "manual=%u generation=%u\n",
                           lane + 1, final_address, final_mask, hint, manuals,
                           observer.generation(lane));
                }
                char path[300], bytes[2048];
                snprintf(path, sizeof(path), "%s/resolv.conf", fixture.resolver);
                text(path, bytes, sizeof(bytes));
                check(!strstr(bytes, "nameserver "), "signal withdraws owned resolver metadata");
                printf("MANAGER_LINK_FINAL_RESOLVER nameservers=0 manual_file=1\n");
                fixture.manual_routes(true);
                finished = true;
            } else
                check(false, "known actual link observation command");
            printf("MANAGER_LINK_PASS stage=%s affected=%u monotonic_ms=%llu\n", command,
                   observer.affected, (unsigned long long)milliseconds());
            if (finished)
                break;
        }
        if (!finished)
            pause_ms(10);
    }
    for (unsigned lane = 0; lane < 2; lane++) {
        uint32_t statistics[2]{};
        socklen_t size = sizeof(statistics);
        check(getsockopt(observer.capture[lane], SOL_PACKET, PACKET_STATISTICS, statistics,
                         &size) == 0 &&
                  size == sizeof(statistics) && !statistics[1],
              "independent capture has no observer drops");
        printf("MANAGER_LINK_CAPTURE index=%u packets=%u dropped=%u failed=%u\n", lane + 1,
               statistics[0], statistics[1], unsigned(observer.capture_failed[lane]));
        check(close(observer.capture[lane]) == 0, "close actual packet observer");
    }
    printf("MANAGER_LINK_COMPLETE scenario=%s affected=%u\n", argv[2], observer.affected);
    return 0;
}
