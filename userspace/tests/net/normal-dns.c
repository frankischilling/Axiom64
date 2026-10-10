// SPDX-License-Identifier: GPL-3.0-or-later
#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>

#ifndef DNS_LINKAGE
#define DNS_LINKAGE "static"
#endif

static void check(int condition, const char* reason) {
    if (!condition) {
        fprintf(stderr, "NORMAL_DNS_FAIL linkage=%s reason=%s errno=%d\n", DNS_LINKAGE, reason,
                errno);
        exit(1);
    }
}

static unsigned long long milliseconds(void) {
    struct timespec now;
    check(clock_gettime(CLOCK_MONOTONIC, &now) == 0, "monotonic clock");
    return (unsigned long long)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

int main(int argc, char** argv) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    check(argc == 3, "phase and healthy adapter mask required");
    const char* phase = argv[1];
    unsigned mask = (unsigned)atoi(argv[2]);
    int recovered = !strcmp(phase, "recovered");
    check((recovered || !strcmp(phase, "initial")) && mask < 4, "bounded phase and mask");
    if (!mask) {
        printf("NORMAL_DNS_SKIP linkage=%s phase=%s mask=0 reason=no-accepted-lease\n", DNS_LINKAGE,
               phase);
        return 0;
    }
    char name[100];
    snprintf(name, sizeof(name), "normal-%s-%s.linux-abi.fixture.", phase, DNS_LINKAGE);
    struct addrinfo hints = {.ai_flags = AI_NUMERICSERV | AI_CANONNAME,
                             .ai_family = AF_INET,
                             .ai_socktype = SOCK_STREAM};
    struct addrinfo* result = NULL;
    unsigned long long started = milliseconds();
    printf("NORMAL_DNS_BEGIN linkage=%s phase=%s mask=%u monotonic_ms=%llu\n", DNS_LINKAGE, phase,
           mask, started);
    int error = getaddrinfo(name, "80", &hints, &result);
    unsigned long long finished = milliseconds();
    if (error)
        fprintf(stderr, "NORMAL_DNS_RESULT error=%d text=%s\n", error, gai_strerror(error));
    check(error == 0 && result && !result->ai_next, "one actual application resolver result");
    check(result->ai_family == AF_INET && result->ai_socktype == SOCK_STREAM &&
              result->ai_protocol == IPPROTO_TCP &&
              result->ai_addrlen == sizeof(struct sockaddr_in),
          "IPv4 stream service metadata");
    const struct sockaddr_in* address = (const struct sockaddr_in*)result->ai_addr;
    check(address && address->sin_family == AF_INET && address->sin_port == htons(80) &&
              ntohl(address->sin_addr.s_addr) == 0x0a173046U + (unsigned)recovered,
          "fresh phase-specific controlled A answer and numeric service port");
    check(result->ai_canonname && strlen(result->ai_canonname) == strlen(name) - 1 &&
              !strncmp(result->ai_canonname, name, strlen(name) - 1),
          "canonical application name remains the requested absolute name");
    check(finished >= started && finished - started <= 6000, "bounded real lookup clock");
    freeaddrinfo(result);
    printf("NORMAL_DNS_PASS linkage=%s phase=%s mask=%u address=10.23.48.%u port=80 "
           "monotonic_ms=%llu elapsed_ms=%llu\n",
           DNS_LINKAGE, phase, mask, 70 + (unsigned)recovered, finished, finished - started);
    return 0;
}
