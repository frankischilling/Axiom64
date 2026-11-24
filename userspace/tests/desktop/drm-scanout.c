// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    userspace/tests/desktop/drm-scanout.c
 * @brief   Exercise the DRM scanout ABI and draw two guest frames.
 * @author  frankischilling
 * @date    2026-11-23
 *
 * Copyright (C) 2026 frankischilling
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://gnu.org/licenses/>.
 */
#define _GNU_SOURCE
#include <drm/drm.h>
#include <drm/drm_fourcc.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/wait.h>
#include <unistd.h>

#define CARD "/dev/dri/card0"
#define CHECK(condition)                                                                           \
    do {                                                                                           \
        if (!(condition)) {                                                                        \
            dprintf(STDERR_FILENO, "DRM_SCANOUT_FAIL line %d: %s (errno=%d)\n", __LINE__,          \
                    #condition, errno);                                                            \
            _exit(1);                                                                              \
        }                                                                                          \
    } while (0)
#define FAILS(call, error) CHECK((call) == -1 && errno == (error))

static void await_capture(const char* marker) {
    char input;
    CHECK(dprintf(STDOUT_FILENO, "%s\n", marker) > 0);
    CHECK(read(STDIN_FILENO, &input, 1) == 1);
}

static void color_frame(void* memory, unsigned pitch, unsigned width, unsigned height,
                        unsigned frame) {
    static const uint32_t colors[] = {0x00ff0000, 0x0000ff00, 0x000000ff, 0x00ffffff};
    for (unsigned y = 0; y < height; ++y) {
        uint32_t* row = (uint32_t*)((uint8_t*)memory + (size_t)y * pitch);
        for (unsigned x = 0; x < width; ++x) {
            unsigned quadrant = (y >= height / 2 ? 2u : 0u) + (x >= width / 2);
            row[x] = colors[(quadrant + frame) % 4];
        }
    }
}

static void test_page_references(int fd) {
    struct drm_mode_create_dumb dumb = {.width = 1, .height = 1, .bpp = 32};
    CHECK(ioctl(fd, DRM_IOCTL_MODE_CREATE_DUMB, &dumb) == 0);
    struct drm_mode_map_dumb map = {.handle = dumb.handle};
    CHECK(ioctl(fd, DRM_IOCTL_MODE_MAP_DUMB, &map) == 0);

    // The GEM handle owns one reference. Each alias takes one more.
    const size_t aliases = UINT16_MAX - 1;
    const size_t page_size = 4096;
    const size_t length = aliases * page_size;
    void* span = mmap(NULL, length, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(span != MAP_FAILED && munmap(span, length) == 0);
    for (size_t i = 0; i < aliases; ++i) {
        void* page = (uint8_t*)span + i * page_size;
        CHECK(mmap(page, page_size, PROT_READ, MAP_SHARED | MAP_FIXED_NOREPLACE, fd, map.offset) ==
              page);
    }
    CHECK(mmap(NULL, page_size, PROT_READ, MAP_SHARED, fd, map.offset) == MAP_FAILED &&
          errno == ENOMEM);
    FAILS(fork(), ENOMEM);
    CHECK(munmap(span, length) == 0);

    pid_t child = fork();
    CHECK(child >= 0);
    if (!child)
        _exit(0);
    int status;
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    struct drm_mode_destroy_dumb destroy = {.handle = dumb.handle};
    CHECK(ioctl(fd, DRM_IOCTL_MODE_DESTROY_DUMB, &destroy) == 0);
}

int main(void) {
    int card = open(CARD, O_RDWR);
    CHECK(card >= 0);
    struct stat st;
    CHECK(fstat(card, &st) == 0 && S_ISCHR(st.st_mode));
    CHECK(major(st.st_rdev) == 226 && minor(st.st_rdev) == 0);

    char driver[32] = {0};
    struct drm_version version = {.name = driver, .name_len = sizeof(driver) - 1};
    CHECK(ioctl(card, DRM_IOCTL_VERSION, &version) == 0);
    CHECK(version.name_len == strlen("axiom64-scanout") && !strcmp(driver, "axiom64-scanout"));

    struct drm_get_cap cap = {.capability = DRM_CAP_DUMB_BUFFER};
    CHECK(ioctl(card, DRM_IOCTL_GET_CAP, &cap) == 0 && cap.value == 1);
    cap.capability = DRM_CAP_ADDFB2_MODIFIERS;
    CHECK(ioctl(card, DRM_IOCTL_GET_CAP, &cap) == 0 && cap.value == 0);
    cap.capability = UINT64_MAX;
    FAILS(ioctl(card, DRM_IOCTL_GET_CAP, &cap), EINVAL);
    FAILS(ioctl(card, DRM_IOCTL_MODE_ATOMIC, NULL), ENOTTY);

    struct drm_mode_card_res resources = {0};
    CHECK(ioctl(card, DRM_IOCTL_MODE_GETRESOURCES, &resources) == 0);
    CHECK(resources.count_fbs == 0 && resources.count_connectors == 1 &&
          resources.count_encoders == 1 && resources.count_crtcs == 1);
    uint32_t output_id = 0, encoder_id = 0, crtc_id = 0;
    resources.connector_id_ptr = (uintptr_t)&output_id;
    resources.encoder_id_ptr = (uintptr_t)&encoder_id;
    resources.crtc_id_ptr = (uintptr_t)&crtc_id;
    CHECK(ioctl(card, DRM_IOCTL_MODE_GETRESOURCES, &resources) == 0);
    CHECK(output_id && encoder_id && crtc_id);

    struct drm_mode_get_connector output = {.connector_id = output_id};
    CHECK(ioctl(card, DRM_IOCTL_MODE_GETCONNECTOR, &output) == 0);
    CHECK(output.count_modes == 1 && output.count_encoders == 1 && output.connection == 1);
    uint32_t output_encoder = 0;
    struct drm_mode_modeinfo mode;
    output.modes_ptr = (uintptr_t)&mode;
    output.encoders_ptr = (uintptr_t)&output_encoder;
    CHECK(ioctl(card, DRM_IOCTL_MODE_GETCONNECTOR, &output) == 0 && output_encoder == encoder_id);
    CHECK(mode.hdisplay == resources.max_width && mode.vdisplay == resources.max_height);
    struct drm_mode_get_encoder encoder = {.encoder_id = encoder_id};
    CHECK(ioctl(card, DRM_IOCTL_MODE_GETENCODER, &encoder) == 0 && encoder.possible_crtcs == 1);

    int other = open(CARD, O_RDWR);
    int alias = dup(card);
    CHECK(other >= 0 && alias >= 0);
    FAILS(ioctl(other, DRM_IOCTL_SET_MASTER), EACCES);
    CHECK(close(card) == 0);

    struct drm_mode_create_dumb dumb = {.width = mode.hdisplay, .height = mode.vdisplay, .bpp = 32};
    struct drm_mode_create_dumb too_wide = dumb;
    too_wide.width = UINT32_MAX;
    FAILS(ioctl(alias, DRM_IOCTL_MODE_CREATE_DUMB, &too_wide), EINVAL);
    CHECK(ioctl(alias, DRM_IOCTL_MODE_CREATE_DUMB, &dumb) == 0);
    CHECK(dumb.handle && dumb.pitch >= dumb.width * 4 && dumb.size >= dumb.pitch * dumb.height);

    struct drm_mode_map_dumb map = {.handle = dumb.handle};
    CHECK(ioctl(alias, DRM_IOCTL_MODE_MAP_DUMB, &map) == 0 && map.offset);
    struct drm_mode_map_dumb foreign = {.handle = dumb.handle};
    FAILS(ioctl(other, DRM_IOCTL_MODE_MAP_DUMB, &foreign), ENOENT);
    CHECK(mmap(NULL, dumb.size, PROT_READ, MAP_SHARED, other, map.offset) == MAP_FAILED);
    CHECK(mmap(NULL, dumb.size, PROT_READ, MAP_PRIVATE, alias, map.offset) == MAP_FAILED);
    CHECK(mmap(NULL, dumb.size + 4096, PROT_READ, MAP_SHARED, alias, map.offset) == MAP_FAILED);
    void* memory = mmap(NULL, dumb.size, PROT_READ | PROT_WRITE, MAP_SHARED, alias, map.offset);
    CHECK(memory != MAP_FAILED && *(uint32_t*)memory == 0);

    uint32_t* page = mmap(NULL, 4096, PROT_READ, MAP_SHARED, alias, map.offset + 4096);
    CHECK(page != MAP_FAILED);
    ((uint32_t*)memory)[1024] = 0x12345678;
    CHECK(*page == 0x12345678 && munmap(page, 4096) == 0);

    uint32_t* existing =
        mmap(NULL, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    CHECK(existing != MAP_FAILED);
    *existing = 0x1234;
    CHECK(mmap(existing, 4096, PROT_READ, MAP_SHARED | MAP_FIXED, alias, map.offset + dumb.size) ==
          MAP_FAILED);
    CHECK(*existing == 0x1234 && munmap(existing, 4096) == 0);

    struct drm_mode_fb_cmd2 fb = {.width = dumb.width,
                                  .height = dumb.height,
                                  .pixel_format = DRM_FORMAT_XRGB8888,
                                  .handles = {dumb.handle},
                                  .pitches = {dumb.pitch}};
    struct drm_mode_fb_cmd2 bad_fb = fb;
    bad_fb.offsets[0] = dumb.size;
    FAILS(ioctl(alias, DRM_IOCTL_MODE_ADDFB2, &bad_fb), EINVAL);
    FAILS(ioctl(other, DRM_IOCTL_MODE_ADDFB2, &fb), ENOENT);
    CHECK(ioctl(alias, DRM_IOCTL_MODE_ADDFB2, &fb) == 0 && fb.fb_id);

    struct drm_gem_close gem = {.handle = dumb.handle};
    CHECK(ioctl(alias, DRM_IOCTL_GEM_CLOSE, &gem) == 0);
    FAILS(ioctl(alias, DRM_IOCTL_MODE_MAP_DUMB, &map), ENOENT);
    CHECK(mmap(NULL, dumb.size, PROT_READ, MAP_SHARED, alias, map.offset) == MAP_FAILED);

    struct drm_mode_crtc crtc = {.crtc_id = crtc_id,
                                 .fb_id = fb.fb_id,
                                 .mode = mode,
                                 .mode_valid = 1,
                                 .set_connectors_ptr = (uintptr_t)&output_id,
                                 .count_connectors = 1};
    FAILS(ioctl(other, DRM_IOCTL_MODE_SETCRTC, &crtc), EACCES);
    CHECK(ioctl(alias, DRM_IOCTL_DROP_MASTER) == 0);
    FAILS(ioctl(alias, DRM_IOCTL_MODE_SETCRTC, &crtc), EACCES);
    CHECK(ioctl(alias, DRM_IOCTL_SET_MASTER) == 0);

    const char* markers[] = {"DRM_SCANOUT_FRAME_ONE", "DRM_SCANOUT_FRAME_TWO"};
    for (unsigned frame = 0; frame < 2; ++frame) {
        color_frame(memory, dumb.pitch, dumb.width, dumb.height, frame);
        if (frame == 0) {
            CHECK(ioctl(alias, DRM_IOCTL_MODE_SETCRTC, &crtc) == 0);
        } else {
            struct drm_clip_rect clips[] = {{0, 0, dumb.width / 2, dumb.height},
                                            {dumb.width / 2, 0, dumb.width, dumb.height}};
            struct drm_mode_fb_dirty_cmd damage = {
                .fb_id = fb.fb_id, .num_clips = 2, .clips_ptr = (uintptr_t)clips};
            FAILS(ioctl(other, DRM_IOCTL_MODE_DIRTYFB, &damage), EACCES);
            clips[1].x2++;
            FAILS(ioctl(alias, DRM_IOCTL_MODE_DIRTYFB, &damage), EINVAL);
            clips[1].x2--;
            CHECK(ioctl(alias, DRM_IOCTL_MODE_DIRTYFB, &damage) == 0);
        }
        struct drm_mode_crtc current = {.crtc_id = crtc_id};
        CHECK(ioctl(alias, DRM_IOCTL_MODE_GETCRTC, &current) == 0 && current.mode_valid &&
              current.fb_id == fb.fb_id);
        await_capture(markers[frame]);
    }

    CHECK(ioctl(alias, DRM_IOCTL_MODE_RMFB, &fb.fb_id) == 0);
    FAILS(ioctl(alias, DRM_IOCTL_MODE_SETCRTC, &crtc), ENOENT);
    CHECK(close(alias) == 0 && ioctl(other, DRM_IOCTL_SET_MASTER) == 0);
    CHECK(*(uint32_t*)memory == 0x0000ff00 && munmap(memory, dumb.size) == 0);
    test_page_references(other);
    CHECK(close(other) == 0);
    CHECK(dprintf(STDOUT_FILENO, "DRM_SCANOUT_GUEST_PASS\n") > 0);
    reboot(RB_POWER_OFF);
    return 1;
}
