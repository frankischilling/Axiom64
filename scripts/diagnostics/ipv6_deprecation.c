// SPDX-License-Identifier: GPL-3.0-or-later
#define main original_router_main
#include "../../userspace/tests/net/ipv6_router.c"
#undef main

#include <sys/wait.h>

int main(int argc, char** argv) {
    check(argc == 3, "diagnostic frame and bounded case count");
    setvbuf(stdout, NULL, _IONBF, 0);
    int source = open(argv[1], O_RDONLY | O_CLOEXEC);
    unsigned char frame[2048];
    ssize_t bytes = read(source, frame, sizeof(frame));
    check(bytes == 214, "original first-PIO frame length");
    close(source);
    unsigned cases = strtoul(argv[2], NULL, 10);
    check(cases > 0 && cases <= 3000, "bounded diagnostic case count");
    int control = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    struct ifreq request = {0};
    strcpy(request.ifr_name, "eth0");
    check(!ioctl(control, SIOCGIFINDEX, &request), "diagnostic index");
    indices[0] = request.ifr_ifindex;
    check(!ioctl(control, SIOCGIFHWADDR, &request), "diagnostic MAC");
    memcpy(macs[0], request.ifr_hwaddr.sa_data, 6);
    request.ifr_flags = IFF_UP;
    check(!ioctl(control, SIOCSIFFLAGS, &request), "diagnostic interface up");
    scalar("eth0", "addr_gen_mode", 0);
    scalar("eth0", "accept_ra", 1);
    scalar("eth0", "autoconf", 1);
    scalar("eth0", "dad_transmits", 1);
    scalar("eth0", "disable_ipv6", 0);
    uint64_t began = now();
    for (;;) {
        struct inventory inventory = snapshot(0);
        const struct address_record* link = find(&inventory, link_address(0));
        if (link && !(link->flags & 0x48))
            break;
        check(now() - began < 5000000000ULL, "diagnostic link-local readiness");
        usleep(20000);
    }
    int packet = socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC, htons(3));
    struct ifreq peer = {0};
    strcpy(peer.ifr_name, "peer0");
    check(!ioctl(control, SIOCGIFINDEX, &peer), "diagnostic peer index");
    struct sockaddr_ll binding = {
        .sll_family = AF_PACKET, .sll_protocol = htons(3), .sll_ifindex = peer.ifr_ifindex};
    check(!bind(packet, (struct sockaddr*)&binding, sizeof(binding)), "diagnostic peer bind");
    for (unsigned attempt = 0; attempt < cases; attempt++) {
        printf("PIO_RACE_CASE attempt=%u observed_ns=%llu\n", attempt, (unsigned long long)now());
        for (unsigned kind = 5; kind <= 8; kind++)
            configured_address(0, kind, 0, kind < 7 ? UINT32_MAX : 6000,
                               kind < 7 ? UINT32_MAX : 10000);
        for (unsigned kind = 5; kind <= 8; kind++)
            first_pio_check(0, kind, "configured");
        check(send(packet, frame, bytes, 0) == bytes, "diagnostic exact original RA send");
        pid_t child = fork();
        check(child >= 0, "diagnostic assertion child");
        if (!child) {
            for (unsigned kind = 5; kind <= 8; kind++)
                first_pio_check(0, kind, "zero");
            _exit(0);
        }
        int status;
        check(waitpid(child, &status, 0) == child && WIFEXITED(status),
              "diagnostic original assertion exit");
        if (WEXITSTATUS(status)) {
            printf("PIO_RACE_REPRODUCED attempt=%u status=%d observed_ns=%llu\n", attempt,
                   WEXITSTATUS(status), (unsigned long long)now());
            uint64_t observation = now();
            unsigned previous[4] = {0};
            while (now() - observation < 125000000000ULL) {
                struct inventory inventory = snapshot(0);
                int complete = 1;
                for (unsigned kind = 5; kind <= 8; kind++) {
                    const struct address_record* address =
                        find(&inventory, prefix_address(0, kind, 1));
                    check(address != NULL, "diagnostic address retained after failure");
                    if (address->flags != previous[kind - 5])
                        printf("PIO_RACE_POST_FAILURE kind=%u flags=%x preferred=%u valid=%u "
                               "elapsed_ns=%llu\n",
                               kind, address->flags, address->preferred, address->valid,
                               (unsigned long long)(now() - observation));
                    previous[kind - 5] = address->flags;
                    complete &= (address->flags & IFA_F_DEPRECATED) != 0;
                }
                if (complete)
                    break;
                usleep(20000);
            }
            return 1;
        }
    }
    printf("PIO_RACE_NOT_REPRODUCED cases=%u\n", cases);
    return 0;
}
