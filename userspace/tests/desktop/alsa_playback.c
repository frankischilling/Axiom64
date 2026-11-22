// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    userspace/tests/desktop/alsa_playback.c
 * @brief   Guest exercise for ALSA hardware playback.
 * @author  frankischilling
 * @date    2026-11-22
 *
 * Exercises Linux ALSA UAPI negotiation, streaming, drain, and OSS ownership.
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
#define _POSIX_C_SOURCE 200809L
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <time.h>
#include <unistd.h>
#include <sound/asound.h>

enum { period = 1024, periods = 14, blocks_per_channel = 24 };

#define CHECK(condition)                                                                           \
    do {                                                                                           \
        if (!(condition)) {                                                                        \
            fprintf(stderr, "PCM_FAIL line=%d errno=%d: %s\n", __LINE__, errno, #condition);       \
            _Exit(1);                                                                              \
        }                                                                                          \
    } while (0)

static struct snd_pcm_hw_params unconstrained(void) {
    struct snd_pcm_hw_params params = {.rmask = ~0u};
    memset(params.masks, 0xff, sizeof(params.masks));
    for (size_t i = 0; i < sizeof(params.intervals) / sizeof(params.intervals[0]); ++i)
        params.intervals[i].max = UINT32_MAX;
    return params;
}

static unsigned frames(const struct snd_pcm_hw_params* params, int index) {
    const struct snd_interval* interval =
        &params->intervals[index - SNDRV_PCM_HW_PARAM_SAMPLE_BITS];
    CHECK(interval->min == interval->max && interval->integer && !interval->empty);
    return interval->min;
}

static void queue_block(int pcm, int block) {
    int16_t samples[period][2];
    for (int i = 0; i < period; ++i) {
        int16_t sign = i % 64 < 32 ? 1 : -1;
        samples[i][0] = block < blocks_per_channel ? 6200 * sign : 0;
        samples[i][1] = block < blocks_per_channel ? 0 : 4100 * sign;
    }
    size_t offset = 0;
    while (offset < period) {
        struct snd_xferi transfer = {.buf = samples + offset, .frames = period - offset};
        CHECK(ioctl(pcm, SNDRV_PCM_IOCTL_WRITEI_FRAMES, &transfer) == 0);
        CHECK(transfer.result > 0 && (uint64_t)transfer.result <= transfer.frames);
        offset += transfer.result;
    }
}

int main(void) {
    struct stat st;
    CHECK(stat("/dev/snd/pcmC0D0p", &st) == 0 && S_ISCHR(st.st_mode));
    CHECK(st.st_gid == 29 && (st.st_mode & 0777) == 0660);
    CHECK(major(st.st_rdev) == 116 && minor(st.st_rdev) == 16);
    CHECK(access("/dev/snd/pcmC0D0c", F_OK) == -1 && errno == ENOENT);

    int control = open("/dev/snd/controlC0", O_RDWR);
    CHECK(control >= 0);
    int version = 0, index = -1;
    CHECK(ioctl(control, SNDRV_CTL_IOCTL_PVERSION, &version) == 0 && version >= 0x20000);
    struct snd_ctl_card_info card;
    CHECK(ioctl(control, SNDRV_CTL_IOCTL_CARD_INFO, &card) == 0 && card.card == 0);
    CHECK(strcmp((char*)card.id, "AxiomHDA") == 0);
    CHECK(ioctl(control, SNDRV_CTL_IOCTL_PCM_NEXT_DEVICE, &index) == 0 && index == 0);
    CHECK(ioctl(control, SNDRV_CTL_IOCTL_PCM_NEXT_DEVICE, &index) == 0 && index == -1);

    struct snd_pcm_info info = {.stream = SNDRV_PCM_STREAM_CAPTURE};
    CHECK(ioctl(control, SNDRV_CTL_IOCTL_PCM_INFO, &info) == -1 && errno == ENODEV);
    memset(&info, 0, sizeof(info));
    CHECK(ioctl(control, SNDRV_CTL_IOCTL_PCM_INFO, &info) == 0 && info.subdevices_avail == 1);

    int pcm = open("/dev/snd/pcmC0D0p", O_RDWR);
    CHECK(pcm >= 0);
    CHECK(open("/dev/snd/pcmC0D0p", O_RDWR) == -1 && errno == EBUSY);
    CHECK(open("/dev/dsp", O_WRONLY) == -1 && errno == EBUSY);
    CHECK(ioctl(control, SNDRV_CTL_IOCTL_PCM_INFO, &info) == 0 && info.subdevices_avail == 0);
    CHECK(close(control) == 0);

    CHECK(ioctl(pcm, SNDRV_PCM_IOCTL_PVERSION, &version) == 0 && version >= 0x20000);
    CHECK(ioctl(pcm, SNDRV_PCM_IOCTL_PREPARE) == -1 && errno == EBADFD);
    struct snd_pcm_hw_params params = unconstrained();
    params.masks[SNDRV_PCM_HW_PARAM_ACCESS].bits[0] = 1u << SNDRV_PCM_ACCESS_MMAP_INTERLEAVED;
    CHECK(ioctl(pcm, SNDRV_PCM_IOCTL_HW_REFINE, &params) == -1 && errno == EINVAL);
    params = unconstrained();
    CHECK(ioctl(pcm, SNDRV_PCM_IOCTL_HW_REFINE, &params) == 0);
    CHECK(!(params.info & SNDRV_PCM_INFO_MMAP));
    CHECK(params.info & 0x40u); // SNDRV_PCM_INFO_PERFECT_DRAIN
    CHECK(params.masks[SNDRV_PCM_HW_PARAM_FORMAT].bits[0] == (1u << SNDRV_PCM_FORMAT_S16_LE));
    CHECK(frames(&params, SNDRV_PCM_HW_PARAM_RATE) == 48000);
    CHECK(frames(&params, SNDRV_PCM_HW_PARAM_CHANNELS) == 2);
    CHECK(frames(&params, SNDRV_PCM_HW_PARAM_PERIOD_SIZE) == period);
    CHECK(frames(&params, SNDRV_PCM_HW_PARAM_BUFFER_SIZE) == period * periods);
    CHECK(ioctl(pcm, SNDRV_PCM_IOCTL_HW_PARAMS, &params) == 0);

    struct snd_pcm_sw_params software = {
        .period_step = 1,
        .avail_min = period,
        .start_threshold = periods * period,
        .stop_threshold = periods * period,
        .tstamp_mode = SNDRV_PCM_TSTAMP_ENABLE,
        .tstamp_type = SNDRV_PCM_TSTAMP_TYPE_MONOTONIC,
    };
    CHECK(ioctl(pcm, SNDRV_PCM_IOCTL_SW_PARAMS, &software) == 0 &&
          software.boundary > period * periods);
    CHECK(ioctl(pcm, SNDRV_PCM_IOCTL_PREPARE) == 0);
    CHECK(ioctl(pcm, SNDRV_PCM_IOCTL_START) == -1 && errno == EPIPE);
    struct pollfd descriptor = {.fd = pcm, .events = POLLOUT};
    CHECK(poll(&descriptor, 1, 0) == 1 && descriptor.revents == POLLOUT);
    struct snd_xferi bad = {.buf = (void*)1, .frames = period};
    CHECK(ioctl(pcm, SNDRV_PCM_IOCTL_WRITEI_FRAMES, &bad) == -1 && errno == EFAULT);

    for (int i = 0; i < periods - 1; ++i)
        queue_block(pcm, i);
    struct snd_pcm_status status;
    CHECK(ioctl(pcm, SNDRV_PCM_IOCTL_STATUS, &status) == 0);
    CHECK(status.state == SNDRV_PCM_STATE_PREPARED && status.hw_ptr == 0);
    CHECK(status.appl_ptr == (periods - 1) * period && status.delay == (periods - 1) * period);
    CHECK(ioctl(pcm, SNDRV_PCM_IOCTL_START) == 0);

    for (int i = periods - 1; i < 2 * blocks_per_channel; ++i)
        queue_block(pcm, i);
    struct snd_pcm_sync_ptr sync = {
        .flags = SNDRV_PCM_SYNC_PTR_HWSYNC | SNDRV_PCM_SYNC_PTR_APPL | SNDRV_PCM_SYNC_PTR_AVAIL_MIN,
    };
    CHECK(ioctl(pcm, SNDRV_PCM_IOCTL_SYNC_PTR, &sync) == 0);
    CHECK(sync.s.status.state == SNDRV_PCM_STATE_RUNNING);
    CHECK(sync.s.status.hw_ptr > 0 && sync.s.status.hw_ptr <= sync.c.control.appl_ptr);
    CHECK(sync.c.control.appl_ptr == 2 * blocks_per_channel * period);
    CHECK(ioctl(pcm, SNDRV_PCM_IOCTL_DRAIN) == 0);
    CHECK(ioctl(pcm, SNDRV_PCM_IOCTL_STATUS, &status) == 0);
    CHECK(status.state == SNDRV_PCM_STATE_SETUP && status.delay == 0 &&
          status.hw_ptr == status.appl_ptr);

    CHECK(ioctl(pcm, SNDRV_PCM_IOCTL_PREPARE) == 0);
    // Keep the ring primed until drain, with no explicit START.
    software.start_threshold = software.boundary;
    CHECK(ioctl(pcm, SNDRV_PCM_IOCTL_SW_PARAMS, &software) == 0);
    int16_t silence[period][2] = {0};
    for (int i = 0; i < periods; ++i) {
        struct snd_xferi transfer = {.buf = silence, .frames = period};
        CHECK(ioctl(pcm, SNDRV_PCM_IOCTL_WRITEI_FRAMES, &transfer) == 0 &&
              transfer.result == period);
    }
    CHECK(ioctl(pcm, SNDRV_PCM_IOCTL_DRAIN) == 0);

    CHECK(ioctl(pcm, SNDRV_PCM_IOCTL_HW_FREE) == 0);
    CHECK(close(pcm) == 0);
    int oss = open("/dev/dsp", O_WRONLY);
    CHECK(oss >= 0);
    CHECK(open("/dev/snd/pcmC0D0p", O_RDWR) == -1 && errno == EBUSY);
    CHECK(close(oss) == 0);
    puts("PCM_ALSA_PASS");
    return 0;
}
