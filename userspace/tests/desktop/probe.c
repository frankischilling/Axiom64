// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#define CHECK(expr)                                                                                \
    do {                                                                                           \
        if (!(expr)) {                                                                             \
            fprintf(stderr, "X11_FAIL line=%d: %s errno=%d\n", __LINE__, #expr, errno);            \
            exit(1);                                                                               \
        }                                                                                          \
    } while (0)

static void transfer(int fd, void* bytes, size_t size, int writing) {
    unsigned char* data = bytes;
    while (size) {
        ssize_t n = writing ? write(fd, data, size) : read(fd, data, size);
        if (n < 0 && errno == EINTR)
            continue;
        CHECK(n > 0);
        data += n;
        size -= n;
    }
}

static uint16_t u16(const void* p) {
    uint16_t value;
    memcpy(&value, p, 2);
    return value;
}

static uint32_t u32(const void* p) {
    uint32_t value;
    memcpy(&value, p, 4);
    return value;
}

static unsigned char* response(int fd, unsigned char header[32], size_t* length) {
    for (;;) {
        transfer(fd, header, 32, 0);
        if (header[0] == 0) {
            fprintf(stderr, "X11 error=%u request=%u minor=%u\n", header[1], header[10],
                    u16(header + 8));
            exit(1);
        }
        if (header[0] == 1)
            break;
    }
    *length = (size_t)u32(header + 4) * 4;
    CHECK(*length <= 16 * 1024 * 1024);
    unsigned char* data = malloc(*length ? *length : 1);
    CHECK(data);
    transfer(fd, data, *length, 0);
    return data;
}

static uint32_t terminal_window(int fd, uint32_t window, uint32_t class_atom, int depth) {
    unsigned char reply[32];
    size_t length;
    uint32_t property[] = {6u << 16 | 20u, window, class_atom, 0, 0, 256};
    transfer(fd, property, sizeof(property), 1);
    unsigned char* value = response(fd, reply, &length);
    int terminal = length >= 5 && memmem(value, length, "XTerm", 5);
    free(value);
    if (terminal) {
        uint32_t attributes[] = {2u << 16 | 3u, window};
        transfer(fd, attributes, sizeof(attributes), 1);
        free(response(fd, reply, &length));
        if (reply[26] == 2)
            return window;
    }
    if (depth == 6)
        return 0;
    uint32_t tree[] = {2u << 16 | 15u, window};
    transfer(fd, tree, sizeof(tree), 1);
    unsigned char* children = response(fd, reply, &length);
    unsigned count = u16(reply + 16);
    CHECK(length >= count * 4);
    uint32_t found = 0;
    for (unsigned i = 0; i < count && !found; ++i)
        found = terminal_window(fd, u32(children + i * 4), class_atom, depth + 1);
    free(children);
    return found;
}

int main(int argc, char** argv) {
    if (argc > 1 && !strcmp(argv[1], "--device")) {
        char target[128] = {0};
        ssize_t n =
            readlink("/sys/class/graphics/fb0/device/subsystem", target, sizeof(target) - 1);
        CHECK(n > 0 && !strcmp(target, "/sys/bus/platform"));
        struct stat info;
        CHECK(stat(target, &info) == 0 && S_ISDIR(info.st_mode));
        int fb = open("/dev/fb0", O_RDWR);
        CHECK(fb >= 0);
        uint32_t var[40];
        unsigned char fixed[80];
        CHECK(ioctl(fb, 0x4600, var) == 0 && var[0] >= 640 && var[1] >= 480 && var[6] == 32);
        CHECK(ioctl(fb, 0x4602, fixed) == 0 && u32(fixed + 48) >= var[0] * 4);
        close(fb);
        puts("FRAMEBUFFER_DEVICE_PASS");
        return 0;
    }
    int ready = argc > 1 && !strcmp(argv[1], "--ready");
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    CHECK(fd >= 0);
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    strcpy(address.sun_path, "/tmp/.X11-unix/X0");
    if (connect(fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        if (ready)
            return 2;
        CHECK(0);
    }
    unsigned char hello[12] = {'l', 0, 11, 0};
    transfer(fd, hello, sizeof(hello), 1);
    unsigned char prefix[8];
    transfer(fd, prefix, 8, 0);
    CHECK(prefix[0] == 1 && u16(prefix + 2) == 11);
    size_t setup_size = (size_t)u16(prefix + 6) * 4;
    CHECK(setup_size >= 32 && setup_size < 1024 * 1024);
    unsigned char* setup = malloc(setup_size);
    CHECK(setup);
    transfer(fd, setup, setup_size, 0);
    size_t screen_offset = 32 + ((u16(setup + 16) + 3) & ~3u) + setup[21] * 8;
    CHECK(screen_offset + 40 <= setup_size && setup[20] > 0);
    const unsigned char* screen = setup + screen_offset;
    uint32_t root = u32(screen), base = u32(setup + 4), visual = u32(screen + 32);
    uint32_t focus[] = {1u << 16 | 43u};
    unsigned char reply[32];
    size_t length;
    transfer(fd, focus, sizeof(focus), 1);
    free(response(fd, reply, &length));
    if (ready) {
        close(fd);
        free(setup);
        return 0;
    }
    if (argc > 1 && !strcmp(argv[1], "--desktop")) {
        uint32_t attributes[] = {2u << 16 | 3u, root};
        transfer(fd, attributes, sizeof(attributes), 1);
        unsigned char* masks = response(fd, reply, &length);
        CHECK(length >= 12 && (u32(masks) & (1u << 20)));
        free(masks);
        puts("WINDOW_MANAGER_PASS");
        uint32_t atom[] = {4u << 16 | 16u, 8, 0, 0};
        memcpy(atom + 2, "WM_CLASS", 8);
        transfer(fd, atom, sizeof(atom), 1);
        free(response(fd, reply, &length));
        uint32_t class_atom = u32(reply + 8), terminal = 0;
        for (int attempt = 0; attempt < 20 && !terminal; ++attempt) {
            terminal = terminal_window(fd, root, class_atom, 0);
            if (!terminal)
                usleep(100000);
        }
        CHECK(terminal);
        uint32_t geometry[] = {2u << 16 | 14u, terminal};
        transfer(fd, geometry, sizeof(geometry), 1);
        free(response(fd, reply, &length));
        unsigned width = u16(reply + 16), height = u16(reply + 18);
        CHECK(width > 200 && height > 100 && width <= u16(screen + 20) &&
              height <= u16(screen + 22));
        uint32_t get_image[] = {5u << 16 | 2u << 8 | 73u, terminal, 0, height << 16 | width,
                                0xffffffff};
        transfer(fd, get_image, sizeof(get_image), 1);
        unsigned char* pixels = response(fd, reply, &length);
        CHECK(length == width * height * 4);
        unsigned different = 0;
        for (size_t i = 4; i < length; i += 4)
            different += u32(pixels + i) != u32(pixels);
        free(pixels);
        CHECK(different > 100);
        uint32_t warp[] = {6u << 16 | 41u, 0, terminal, 0, 0, 100u << 16 | 100u};
        transfer(fd, warp, sizeof(warp), 1);
        uint32_t set_focus[] = {3u << 16 | 42u, terminal, 0};
        transfer(fd, set_focus, sizeof(set_focus), 1);
        transfer(fd, focus, sizeof(focus), 1);
        free(response(fd, reply, &length));
        CHECK(u32(reply + 8) == terminal);
        puts("XTERM_WINDOW_PASS");
        printf("XTERM_WINDOW_ID window=%u\n", terminal);
        close(fd);
        free(setup);
        return 0;
    }
    uint32_t window = base | 1, gc = base | 2;
    const uint32_t color = 0x225577;
    uint32_t create[] = {10u << 16 | (uint32_t)screen[38] << 8 | 1u,
                         window,
                         root,
                         100u << 16 | 160u,
                         200u << 16 | 300u,
                         1u << 16,
                         visual,
                         2u | 1u << 11,
                         0x111b29,
                         0};
    transfer(fd, create, sizeof(create), 1);
    uint32_t map[] = {2u << 16 | 8u, window};
    transfer(fd, map, sizeof(map), 1);
    uint32_t create_gc[] = {5u << 16 | 55u, gc, window, 4, color};
    transfer(fd, create_gc, sizeof(create_gc), 1);
    uint32_t rectangles[] = {5u << 16 | 70u, window, gc, 0, 200u << 16 | 300u};
    transfer(fd, rectangles, sizeof(rectangles), 1);
    uint32_t get_image[] = {5u << 16 | 2u << 8 | 73u, window, 0, 200u << 16 | 300u, 0xffffffff};
    transfer(fd, get_image, sizeof(get_image), 1);
    unsigned char* pixels = response(fd, reply, &length);
    CHECK(reply[1] == 24 && length == 300 * 200 * 4 && (u32(pixels) & 0xffffff) == color);
    CHECK((u32(pixels + 4 * (100 * 300 + 150)) & 0xffffff) == color);
    free(pixels);
    usleep(100000);
    int framebuffer = open("/dev/fb0", O_RDWR);
    CHECK(framebuffer >= 0);
    uint32_t var[40];
    unsigned char fixed[80];
    CHECK(ioctl(framebuffer, 0x4600, var) == 0);
    CHECK(ioctl(framebuffer, 0x4602, fixed) == 0 && var[6] == 32);
    uint32_t pitch = u32(fixed + 48);
    size_t bytes = (size_t)pitch * var[1];
    unsigned char* mapping = mmap(0, bytes, PROT_READ, MAP_SHARED, framebuffer, 0);
    CHECK(mapping != MAP_FAILED);
    CHECK((u32(mapping + 120 * pitch + 180 * 4) & 0xffffff) == color);
    CHECK(munmap(mapping, bytes) == 0);
    close(framebuffer);
    close(fd);
    free(setup);
    puts("X11_PROTOCOL_PIXELS_PASS");
    return 0;
}
