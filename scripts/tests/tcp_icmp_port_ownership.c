// SPDX-License-Identifier: GPL-3.0-or-later
#define main tcp_icmp_contract_main
#include "../../userspace/tests/net/tcp_icmp.c"
#undef main

static struct sockaddr_in local_address(unsigned port) {
    return (struct sockaddr_in){
        .sin_family = AF_INET, .sin_port = htons(port), .sin_addr.s_addr = htonl(0x0a170102)};
}

static void wait_time_wait(unsigned port) {
    uint64_t deadline = milliseconds() + 3000;
    do {
        FILE* table = fopen("/proc/net/tcp", "r");
        CHECK(table);
        char line[512];
        int found = 0;
        while (fgets(line, sizeof(line), table)) {
            unsigned address, local_port, peer, peer_port, state;
            if (sscanf(line, " %*u: %x:%x %x:%x %x", &address, &local_port, &peer, &peer_port,
                       &state) == 5 &&
                address == 0x0201170a && local_port == port && state == 6)
                found = 1;
        }
        CHECK(!fclose(table));
        if (found)
            return;
        usleep(1000);
    } while (milliseconds() < deadline);
    CHECK(!"missing actual TIME_WAIT owner");
}

int main(int argc, char** argv) {
    CHECK(argc == 2);
    native = 1;
    int history = strcmp(argv[1], "fresh") != 0;
    int closed = !strcmp(argv[1], "closed");
    int dummy = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in blocked = local_address(41002);
    CHECK(dummy >= 0 && !bind(dummy, (struct sockaddr*)&blocked, sizeof(blocked)));
    passive_start();
    int server = -1, client = -1, accepted = -1;
    unsigned selected = 0;
    if (history) {
        server = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in address = {
            .sin_family = AF_INET, .sin_port = htons(48037), .sin_addr.s_addr = htonl(0x0a170101)};
        CHECK(server >= 0 && !bind(server, (struct sockaddr*)&address, sizeof(address)) &&
              !listen(server, 1));
        client = socket(AF_INET, SOCK_STREAM, 0);
        int enabled = 1;
        struct sockaddr_in source = local_address(0);
        CHECK(client >= 0 && !setsockopt(client, IPPROTO_IP, 24, &enabled, sizeof(enabled)) &&
              !bind(client, (struct sockaddr*)&source, sizeof(source)));
        CHECK(!connect(client, (struct sockaddr*)&address, sizeof(address)));
        accepted = accept(server, NULL, NULL);
        socklen_t size = sizeof(source);
        CHECK(accepted >= 0 && !getsockname(client, (struct sockaddr*)&source, &size));
        selected = ntohs(source.sin_port);
        printf("TCP_ICMP_AUTOMATIC_PORT selected=%u history=%s\n", selected, argv[1]);
        fflush(stdout);
        if (closed) {
            CHECK(!close(client));
            client = -1;
            char byte;
            CHECK(!read(accepted, &byte, 1) && !close(accepted));
            accepted = -1;
            wait_time_wait(selected);
        }
    }
    cycle_ports_release();
    int baseline = open("/dev/null", O_RDONLY);
    CHECK(baseline >= 0 && !close(baseline));
    int fd = cycle_socket(0, baseline);
    CHECK(fd >= 0 && !close(fd));
    if (history)
        CHECK(selected != 41000);
    if (client >= 0)
        CHECK(!close(client));
    if (accepted >= 0)
        CHECK(!close(accepted));
    if (server >= 0)
        CHECK(!close(server));
    CHECK(!close(dummy));
    puts("TCP_ICMP_PORT_OWNERSHIP_PASS automatic_source_fixed_reclamation");
    return 0;
}
