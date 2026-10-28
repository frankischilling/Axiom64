// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <unistd.h>

static void check(int condition, const char* label) {
    if (!condition) {
        fprintf(stderr, "IPV4_COPY_MODEL_FAIL %s errno=%d\n", label, errno);
        exit(1);
    }
}

int main(void) {
    struct utsname kernel;
    check(!uname(&kernel), "actual kernel identity");
    printf("IPV4_COPY_MODEL_KERNEL release=%s\n", kernel.release);
    long page = sysconf(_SC_PAGESIZE);
    check(page >= 4096, "actual guard page size");
    unsigned char* guards =
        mmap(NULL, (size_t)page * 4, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    check(guards != MAP_FAILED, "owned guards");
    for (unsigned mode = 0; mode < 4; mode++) {
        check(!mprotect(guards, (size_t)page * 4, PROT_READ | PROT_WRITE), "reset guards");
        memset(guards, 0xa5, (size_t)page * 4);
        int receiver = socket(AF_INET, SOCK_DGRAM, 0), sender = socket(AF_INET, SOCK_DGRAM, 0);
        check(receiver >= 0 && sender >= 0, "actual descriptions");
        struct sockaddr_in target = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(0x7f000002)};
        struct sockaddr_in source = {
            .sin_family = AF_INET, .sin_port = htons(53598), .sin_addr.s_addr = htonl(0x7f000001)};
        check(!bind(receiver, (struct sockaddr*)&target, sizeof(target)) &&
                  !bind(sender, (struct sockaddr*)&source, sizeof(source)),
              "private endpoint bindings");
        socklen_t size = sizeof(target);
        check(!getsockname(receiver, (struct sockaddr*)&target, &size) && size == sizeof(target),
              "actual destination");
        unsigned char sent = 0x5a, payload = 0xa5, name[40];
        memset(name, 0xa5, sizeof(name));
        check(sendto(sender, &sent, 1, 0, (struct sockaddr*)&target, sizeof(target)) == 1,
              "actual input");
        struct pollfd ready = {.fd = receiver, .events = POLLIN};
        check(poll(&ready, 1, 1000) == 1 && (ready.revents & POLLIN), "input readiness");
        unsigned char* output = mode == 0 || mode == 3 ? guards + page - 1 : name;
        socklen_t ordinary = 40;
        socklen_t* length = mode == 1 ? (void*)(guards + page * 3) : &ordinary;
        memcpy(length, &ordinary, sizeof(ordinary));
        struct iovec vector = {&payload, 1};
        struct msghdr message = {
            .msg_name = output, .msg_namelen = 40, .msg_iov = &vector, .msg_iovlen = 1};
        void* header = &message;
        if (mode == 2) {
            header = guards + page * 3 - 8;
            memcpy(header, &message, sizeof(message));
        }
        if (mode == 0 || mode == 3)
            check(!mprotect(guards + page, (size_t)page, PROT_NONE), "source guard");
        else
            check(!mprotect(guards + page * 3, (size_t)page, PROT_READ), "length guard");
        errno = 0;
        long result =
            mode < 2 ? syscall(SYS_recvfrom, receiver, &payload, 1, MSG_DONTWAIT, output, length)
                     : syscall(SYS_recvmsg, receiver, header, MSG_DONTWAIT);
        int error = result < 0 ? errno : 0;
        uint32_t actual;
        memcpy(&actual, mode < 2 ? (void*)length : (unsigned char*)header + 8, sizeof(actual));
        printf("IPV4_COPY_MODEL_CASE mode=%u result=%ld errno=%d length=%u payload=%u name=", mode,
               result, error, actual, payload);
        for (unsigned n = 0; n < (mode == 0 || mode == 3 ? 1u : 40u); n++)
            printf("%02x", output[n]);
        puts("");
        check(result == -1 && error == EFAULT && payload == sent,
              "actual post-payload source fault");
        errno = 0;
        check(recv(receiver, &payload, 1, MSG_DONTWAIT) == -1 && errno == EAGAIN,
              "fault consumed its original input");
        check(!close(sender) && !close(receiver), "release probe descriptions");
    }
    check(!munmap(guards, (size_t)page * 4), "release guards");
    puts("IPV4_COPY_MODEL_DONE cases=4");
    return 0;
}
