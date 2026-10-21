// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/utsname.h>
#include <unistd.h>

static void check(int value, const char* what) {
    if (!value) {
        fprintf(stderr, "IPV6_COPY_MODEL_FAIL %s errno=%d\n", what, errno);
        exit(1);
    }
}

int main(void) {
    struct utsname kernel;
    check(!uname(&kernel), "actual kernel");
    printf("IPV6_COPY_MODEL_KERNEL release=%s\n", kernel.release);
    unsigned char* pages =
        mmap(NULL, 8192, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    unsigned char* lengths =
        mmap(NULL, 8192, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    check(pages != MAP_FAILED && lengths != MAP_FAILED && !mprotect(pages + 4096, 4096, PROT_NONE),
          "owned guards");
    for (unsigned mode = 0; mode < 2; mode++) {
        int receiver = socket(AF_INET6, SOCK_DGRAM, 0), sender = socket(AF_INET6, SOCK_DGRAM, 0);
        check(receiver >= 0 && sender >= 0, "descriptions");
        struct sockaddr_in6 target = {.sin6_family = AF_INET6, .sin6_addr = IN6ADDR_LOOPBACK_INIT};
        check(!bind(receiver, (struct sockaddr*)&target, 28), "receive bind");
        socklen_t size = 28;
        check(!getsockname(receiver, (struct sockaddr*)&target, &size) && size == 28,
              "actual target");
        struct sockaddr_in6 source = {
            .sin6_family = AF_INET6, .sin6_port = htons(53570), .sin6_addr = IN6ADDR_LOOPBACK_INIT};
        check(!bind(sender, (struct sockaddr*)&source, 28), "owned source");
        unsigned char sent = 0x5a, payload = 0xa5, name[40];
        memset(name, 0xa5, 40);
        memset(pages, 0xa5, 4096);
        check(sendto(sender, &sent, 1, 0, (struct sockaddr*)&target, 28) == 1, "actual input");
        struct pollfd ready = {.fd = receiver, .events = POLLIN};
        check(poll(&ready, 1, 1000) == 1 && ready.revents == POLLIN, "input readiness");
        check(!mprotect(lengths + 4096, 4096, PROT_READ | PROT_WRITE), "prepare length");
        socklen_t ordinary = 40, *length = mode ? (socklen_t*)(lengths + 4096) : &ordinary;
        *length = 40;
        if (mode)
            check(!mprotect(lengths + 4096, 4096, PROT_READ), "protected output length");
        unsigned char* output = mode ? name : pages + 4095;
        errno = 0;
        long result =
            recvfrom(receiver, &payload, 1, MSG_DONTWAIT, (struct sockaddr*)output, length);
        int error = result < 0 ? errno : 0;
        printf("IPV6_COPY_MODEL_CASE mode=%u result=%ld errno=%d length=%u payload=%u name=", mode,
               result, error, *length, payload);
        for (unsigned at = 0; at < (mode ? 40 : 1); at++)
            printf("%02x", output[at]);
        puts("");
        check(result == -1 && error == EFAULT && payload == sent, "actual protected receive");
        errno = 0;
        check(recv(receiver, &payload, 1, MSG_DONTWAIT) == -1 && errno == EAGAIN,
              "fault consumes input");
        check(!close(sender) && !close(receiver), "retire ownership");
    }
    check(!munmap(pages, 8192) && !munmap(lengths, 8192), "release guards");
    puts("IPV6_COPY_MODEL_DONE cases=2");
    return 0;
}
