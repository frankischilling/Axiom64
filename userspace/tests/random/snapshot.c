// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/random.h>
#include <termios.h>
#include <unistd.h>

#ifndef RANDOM_LINKAGE
#define RANDOM_LINKAGE "static"
#endif

static void require(int condition, const char* operation) {
    if (!condition) {
        fprintf(stderr, "RANDOM_SNAPSHOT_FAIL operation=%s error=%d\n", operation, errno);
        exit(1);
    }
}

static int entropy_count(void) {
    int fd = open("/dev/random", O_RDONLY | O_CLOEXEC);
    require(fd >= 0, "random-open");
    int bits = -1;
    require(ioctl(fd, 0x80045200U, &bits) == 0 && close(fd) == 0, "entropy-count");
    return bits;
}

int main(int argc, char** argv) {
    setbuf(stdout, NULL);
    require(argc == 2 && (!strcmp(argv[1], "ready") || !strcmp(argv[1], "unready")), "arguments");
    int ready = !strcmp(argv[1], "ready");
    struct termios terminal;
    require(tcgetattr(0, &terminal) == 0, "terminal-get");
    terminal.c_lflag &= ~(ICANON | ECHO);
    terminal.c_cc[VMIN] = 1;
    terminal.c_cc[VTIME] = 0;
    require(tcsetattr(0, TCSANOW, &terminal) == 0, "terminal-set");
    require(entropy_count() == (ready ? 256 : 0), "initial-readiness");
    puts("RANDOM_SNAPSHOT_WAIT");
    unsigned samples = 0;
    for (;;) {
        unsigned char command = 0;
        ssize_t count;
        do {
            count = read(0, &command, 1);
        } while (count < 0 && errno == EINTR);
        require(count == 1, "serial-command");
        if (command == 'Q')
            break;
        require(command == 'R', "sample-command");
        unsigned char output[32];
        errno = 0;
        ssize_t result = getrandom(output, sizeof(output), GRND_NONBLOCK);
        if (ready) {
            require(result == sizeof(output), "initialized-output");
            printf("RANDOM_SNAPSHOT_SAMPLE index=%u value=", ++samples);
            for (unsigned i = 0; i < sizeof(output); i++)
                printf("%02x", output[i]);
            puts("");
        } else {
            require(result == -1 && errno == EAGAIN && entropy_count() == 0, "unready-output");
            printf("RANDOM_SNAPSHOT_UNREADY index=%u result=EAGAIN entropy_bits=0\n", ++samples);
        }
    }
    printf("RANDOM_SNAPSHOT_PASS linkage=%s mode=%s samples=%u entropy_bits=%d\n", RANDOM_LINKAGE,
           argv[1], samples, entropy_count());
    return 0;
}
