// SPDX-License-Identifier: GPL-3.0-or-later
// Exercise actual record emission before adding asynchronous conflict controls.
#define main ready_device_fixture_main
#include "ipv6_device_lifecycle.c"
#undef main

static unsigned calls;
static int mode;
static char captured[256];
static size_t captured_size;

ssize_t __wrap_write(int fd, const void* bytes, size_t size) {
    check(fd == STDOUT_FILENO && !calls++ && size > 0 && size < sizeof(captured),
          "one complete actual device record write");
    memcpy(captured, bytes, size);
    captured_size = size;
    if (mode == 1)
        return size - 1;
    if (mode == 2) {
        errno = EINTR;
        return -1;
    }
    return size;
}

int main(int argc, char** argv) {
    check(argc == 2, "one device record case");
    mode = !strcmp(argv[1], "short") ? 1 : !strcmp(argv[1], "interrupted") ? 2 : 0;
    int maximum = !strcmp(argv[1], "maximum");
    check(mode || maximum || !strcmp(argv[1], "ordinary"), "known device record case");
    unsigned char frame[60] = {0};
    frame[18] = 1;
    frame[19] = maximum ? 254 : 7;
    frame[20] = ADDRESS;
    frame[21] = 2;
    frame[22] = 0;
    frame[23] = 4;
    uint32_t fields[] = {htonl(maximum ? UINT32_MAX : 0x880), UINT32_MAX, UINT32_MAX};
    memcpy(frame + 24, fields, sizeof(fields));
    check(inet_pton(AF_INET6, "fe80::1234:5678:9abc:def0", frame + 36) == 1,
          "actual device record address");
    emit_control_record(frame, maximum ? UINT64_MAX : 123456789);
    check(calls == 1 && captured_size && captured[captured_size - 1] == '\n',
          "one retained newline-terminated device record");
    check(fwrite(captured, 1, captured_size, stdout) == captured_size,
          "expose actual recorded bytes");
    return 0;
}
