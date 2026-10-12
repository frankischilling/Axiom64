// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <stdint.h>
#include <termios.h>
#include <unistd.h>

static int input_flush(int operation) {
    int master = posix_openpt(O_RDWR | O_NOCTTY | O_CLOEXEC);
    if (master < 0 || grantpt(master) < 0 || unlockpt(master) < 0)
        return 0;
    char path[64];
    if (ptsname_r(master, path, sizeof(path)))
        return 0;
    int slave = open(path, O_RDWR | O_NOCTTY | O_CLOEXEC);
    struct termios original = {0};
    if (slave < 0 || tcgetattr(slave, &original) < 0)
        return 0;
    struct termios quiet = original;
    quiet.c_lflag &= ~(ICANON | ECHO | ECHONL);
    if (tcsetattr(slave, TCSANOW, &quiet) < 0 || write(master, "old-part", 8) != 8)
        return 0;
    // Observe received input before flushing. A write may otherwise still be
    // in Linux's asynchronous flip buffer rather than its line discipline.
    for (unsigned attempt = 0;; attempt++) {
        int queued = 0;
        if (ioctl(slave, FIONREAD, &queued) < 0 || attempt == 1000)
            return 0;
        if (queued == 8)
            break;
        usleep(1000);
    }
    errno = 0;
    int result = operation == 1 ? tcflush(slave, TCIFLUSH)
                                : tcsetattr(operation == 2 ? master : slave, TCSAFLUSH, &original);
    int error = result < 0 ? errno : 0;
    if (write(master, "new\n", 4) != 4)
        return 0;
    char bytes[64] = {0};
    alarm(5);
    ssize_t count = read(slave, bytes, sizeof(bytes));
    alarm(0);
    struct termios after = {0};
    int flags = tcgetattr(slave, &after) == 0 &&
                (after.c_lflag & (ECHO | ICANON)) ==
                    ((operation == 1 ? quiet : original).c_lflag & (ECHO | ICANON));
    int passed = !result && count == 4 && !memcmp(bytes, "new\n", 4) && flags;
    printf("TERMINAL_FLUSH_RESULT kind=%s result=%d errno=%d bytes=%zd flags=%d passed=%d\n",
           operation == 1   ? "TCIFLUSH"
           : operation == 2 ? "MASTER_TCSETSF"
                            : "TCSETSF",
           result, error, count, flags, passed);
    close(slave);
    close(master);
    return passed;
}

static int pair(int* master, int* slave, struct termios* quiet) {
    *master = posix_openpt(O_RDWR | O_NOCTTY | O_CLOEXEC);
    if (*master < 0 || grantpt(*master) < 0 || unlockpt(*master) < 0)
        return 0;
    char path[64];
    if (ptsname_r(*master, path, sizeof(path)))
        return 0;
    *slave = open(path, O_RDWR | O_NOCTTY | O_CLOEXEC);
    if (*slave < 0 || tcgetattr(*slave, quiet) < 0)
        return 0;
    quiet->c_lflag &= ~(ICANON | ECHO | ECHONL);
    return tcsetattr(*slave, TCSANOW, quiet) == 0;
}

static int received(int fd, int expected) {
    for (unsigned attempt = 0; attempt < 1000; attempt++) {
        int queued = 0;
        if (ioctl(fd, FIONREAD, &queued) < 0)
            return 0;
        if (queued == expected)
            return 1;
        usleep(1000);
    }
    return 0;
}

static int errors_preserve_input(void) {
    int master, slave;
    struct termios quiet = {0}, after = {0};
    if (!pair(&master, &slave, &quiet) || write(master, "old-part", 8) != 8 || !received(slave, 8))
        return 0;
    int passed = 1;
    const unsigned long invalid[] = {3, (unsigned long)-1, 1ul << 32};
    for (unsigned i = 0; i < sizeof(invalid) / sizeof(*invalid); i++) {
        errno = 0;
        passed &= ioctl(slave, TCFLSH, invalid[i]) == -1 && errno == EINVAL && received(slave, 8);
    }
    size_t page = (size_t)sysconf(_SC_PAGESIZE);
    char* mapping =
        mmap(NULL, page * 2, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mapping == MAP_FAILED || mprotect(mapping + page, page, PROT_NONE) < 0)
        return 0;
    uint32_t* incomplete = (uint32_t*)(mapping + page - 8);
    incomplete[0] = quiet.c_iflag ^ ICRNL;
    incomplete[1] = quiet.c_oflag ^ ONLCR;
    errno = 0;
    passed &= ioctl(slave, TCSETSF, incomplete) == -1 && errno == EFAULT;
    passed &= tcgetattr(slave, &after) == 0 && after.c_iflag == quiet.c_iflag &&
              after.c_oflag == quiet.c_oflag && after.c_lflag == quiet.c_lflag &&
              received(slave, 8);
    char bytes[8];
    passed &= read(slave, bytes, sizeof(bytes)) == 8 && !memcmp(bytes, "old-part", 8);
    passed &= munmap(mapping, page * 2) == 0;
    printf("TERMINAL_FLUSH_RESULT kind=ERRORS_PRESERVE_INPUT passed=%d\n", passed);
    close(slave);
    close(master);
    return passed;
}

static int delivered_output(void) {
    int master, slave;
    struct termios quiet = {0};
    if (!pair(&master, &slave, &quiet))
        return 0;
    int passed = write(slave, "out-part", 8) == 8 && received(master, 8) &&
                 tcflush(slave, TCOFLUSH) == 0 && received(master, 8);
    char bytes[8];
    passed &= read(master, bytes, 8) == 8 && !memcmp(bytes, "out-part", 8);
    passed &= write(master, "old-part", 8) == 8 && write(slave, "out-part", 8) == 8 &&
              received(slave, 8) && received(master, 8) && tcflush(slave, TCIOFLUSH) == 0 &&
              received(slave, 0) && received(master, 8);
    passed &= read(master, bytes, 8) == 8 && !memcmp(bytes, "out-part", 8);
    printf("TERMINAL_FLUSH_RESULT kind=DELIVERED_OUTPUT_SURVIVES_TCOFLUSH_TCIOFLUSH passed=%d\n",
           passed);
    close(slave);
    close(master);
    return passed;
}

static int master_input(void) {
    int master, slave;
    struct termios quiet = {0};
    if (!pair(&master, &slave, &quiet))
        return 0;
    int passed = write(slave, "out-part", 8) == 8 && received(master, 8) &&
                 tcflush(master, TCIFLUSH) == 0 && received(master, 0);
    passed &= write(master, "old-part", 8) == 8 && received(slave, 8) &&
              tcflush(master, TCOFLUSH) == 0 && received(slave, 8);
    char bytes[8];
    passed &= read(slave, bytes, 8) == 8 && !memcmp(bytes, "old-part", 8);
    printf("TERMINAL_FLUSH_RESULT kind=MASTER_INPUT_AND_DELIVERED_PEER_INPUT passed=%d\n", passed);
    close(slave);
    close(master);
    return passed;
}

int main(void) {
    alarm(10);
    int passed = input_flush(0);
    passed &= input_flush(1);
    passed &= input_flush(2);
    passed &= errors_preserve_input();
    passed &= delivered_output();
    passed &= master_input();
    alarm(0);
    if (passed)
        puts("TERMINAL_FLUSH_PASS cases=6");
    return passed ? 0 : 1;
}
