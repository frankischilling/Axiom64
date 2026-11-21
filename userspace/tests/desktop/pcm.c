// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    userspace/tests/desktop/pcm.c
 * @brief   Guest exercise for PCM playback and capture.
 * @author  frankischilling
 * @date    2026-11-21
 *
 * Checks OSS controls, device permissions, sample delivery and reset.
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

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define DSP_RESET 0x5000
#define DSP_SYNC 0x5001
#define DSP_SPEED 0xc0045002
#define DSP_GETBLKSIZE 0xc0045004
#define DSP_SETFMT 0xc0045005
#define DSP_CHANNELS 0xc0045006
#define DSP_GETFMTS 0x8004500b
#define DSP_GETOSPACE 0x8010500c
#define DSP_GETISPACE 0x8010500d
#define DSP_GETCAPS 0x8004500f
#define DSP_SETDUPLEX 0x5016
#define FRAMES 48000

static int16_t tone[FRAMES][2], input[4096][2];

static void require(int condition, const char* description) {
    if (!condition) {
        fprintf(stderr, "PCM_FAIL %s errno=%d\n", description, errno);
        reboot(RB_POWER_OFF);
        _Exit(1);
    }
}

static void all(int fd, void* buffer, size_t length, int writing) {
    unsigned char* bytes = buffer;
    while (length) {
        ssize_t done = writing ? write(fd, bytes, length) : read(fd, bytes, length);
        if (done < 0 && errno == EAGAIN) {
            struct pollfd event = {fd, writing ? POLLOUT : POLLIN, 0};
            require(poll(&event, 1, 2000) == 1 && (event.revents & event.events), "PCM ready");
            continue;
        }
        require(done > 0, writing ? "write PCM" : "read PCM");
        bytes += done;
        length -= (size_t)done;
    }
}

static void configure(int fd, int rate, int channels) {
    int value = 0;
    require(ioctl(fd, DSP_GETFMTS, &value) == 0 && value == 0x10, "format mask");
    require(ioctl(fd, DSP_SETFMT, &value) == 0 && value == 0x10, "select s16le");
    value = rate;
    require(ioctl(fd, DSP_SPEED, &value) == 0 && value == rate, "sample rate");
    value = channels;
    require(ioctl(fd, DSP_CHANNELS, &value) == 0 && value == channels, "channel count");
    require(ioctl(fd, DSP_GETBLKSIZE, &value) == 0 && value == 4096, "fragment size");
}

static void playback(void) {
    const int fd = open("/dev/dsp", O_WRONLY);
    require(fd >= 0, "open playback");
    require(open("/dev/dsp", O_WRONLY | O_NONBLOCK) == -1 && errno == EBUSY, "second writer");
    const int copy = dup(fd);
    require(copy >= 0 && close(fd) == 0, "duplicate ownership");
    require(open("/dev/dsp", O_WRONLY) == -1 && errno == EBUSY, "duplicate holds ownership");
    require(ioctl(copy, DSP_SPEED, 0) == -1 && errno == EFAULT, "invalid ioctl address");
    configure(copy, 48000, 2);
    int space[4];
    require(ioctl(copy, DSP_GETOSPACE, space) == 0 && space[0] > 0 && space[2] == 4096 &&
                space[3] == space[0] * space[2],
            "initial space");
    struct pollfd event = {copy, POLLOUT, 0};
    require(poll(&event, 1, 0) == 1 && (event.revents & POLLOUT), "poll playback");
    for (unsigned i = 0; i < FRAMES; ++i) {
        int amplitude = 4600 + (int)(i / 6000) * 410;
        tone[i][0] = i % 48 < 24 ? amplitude : -amplitude;
        tone[i][1] = i % 32 < 16 ? -amplitude / 2 : amplitude / 2;
    }
    all(copy, tone, 13, 1);
    all(copy, (unsigned char*)tone + 13, sizeof(tone) - 13, 1);
    int notification[2];
    require(pipe(notification) == 0, "drain notification pipe");
    pid_t worker = fork();
    require(worker >= 0, "drain worker");
    if (!worker) {
        struct timespec delay = {0, 20000000}, completed;
        close(notification[0]);
        if (nanosleep(&delay, NULL) || clock_gettime(CLOCK_MONOTONIC, &completed) ||
            write(notification[1], &completed, sizeof(completed)) != sizeof(completed))
            _Exit(1);
        _Exit(0);
    }
    close(notification[1]);
    require(ioctl(copy, DSP_SYNC) == 0, "drain stereo");
    struct timespec drained, completed;
    require(clock_gettime(CLOCK_MONOTONIC, &drained) == 0, "drain time");
    require(read(notification[0], &completed, sizeof(completed)) == sizeof(completed),
            "another process ran during drain");
    const long ahead =
        (drained.tv_sec - completed.tv_sec) * 1000000000L + drained.tv_nsec - completed.tv_nsec;
    require(ahead >= 20000000 && close(notification[0]) == 0, "drain did not stall the guest");
    int worker_status;
    require(waitpid(worker, &worker_status, 0) == worker && worker_status == 0,
            "drain worker exit");
    require(ioctl(copy, DSP_RESET) == 0 && close(copy) == 0, "reset and close");
    const int mono = open("/dev/dsp", O_WRONLY);
    require(mono >= 0, "open after last close");
    configure(mono, 22050, 1);
    for (unsigned i = 0; i < 2048; ++i)
        tone[i][0] = i % 36 < 18 ? 5300 : -5300;
    int16_t alternate[2048];
    for (unsigned i = 0; i < 2048; ++i)
        alternate[i] = tone[i][0];
    all(mono, alternate, sizeof(alternate), 1);
    require(ioctl(mono, DSP_SYNC) == 0 && close(mono) == 0, "drain mono");
    puts("PCM_PLAYBACK_PASS");
}

static void capture(void) {
    const int fd = open("/dev/dsp", O_RDWR | O_NONBLOCK);
    require(fd >= 0, "open duplex");
    int caps = 0;
    require(ioctl(fd, DSP_GETCAPS, &caps) == 0 && (caps & 0x100) && ioctl(fd, DSP_SETDUPLEX) == 0,
            "report duplex");
    configure(fd, 48000, 2);
    require(read(fd, input, 4) == -1 && errno == EAGAIN, "empty nonblocking capture");
    for (unsigned i = 0; i < 4096; ++i) {
        tone[i][0] = i % 48 < 24 ? 7500 : -7500;
        tone[i][1] = i % 32 < 16 ? -3500 : 3500;
    }
    all(fd, tone, 4096 * 4, 1);
    struct pollfd event = {fd, POLLIN, 0};
    require(poll(&event, 1, 2000) == 1 && (event.revents & POLLIN), "poll capture");
    int space[4];
    require(ioctl(fd, DSP_GETISPACE, space) == 0 && space[0] && space[3] >= 4096, "capture space");
    unsigned samples = 0, pairs = 0, transitions = 0;
    for (unsigned round = 0; round < 20; ++round) {
        require(poll(&event, 1, 2000) == 1 && (event.revents & POLLIN), "continued capture");
        const ssize_t size = read(fd, input, sizeof(input));
        if (size < 4096 || size % 4)
            fprintf(stderr, "capture round=%u size=%zd revents=%d\n", round, size, event.revents);
        require(size >= 4096 && size % 4 == 0, "captured frames");
        for (unsigned j = 0; j < (size_t)size / 4; ++j) {
            const int left = input[j][0], right = input[j][1];
            samples += abs(left) > 1900;
            pairs += abs(left) > 1900 && abs(left + 2 * right) < 32;
            transitions += j && (left < 0) != (input[j - 1][0] < 0);
        }
    }
    require(samples > 8000 && pairs > 8000 && transitions > 80, "recorded host waveform");
    struct timespec overrun = {0, 650000000};
    require(nanosleep(&overrun, NULL) == 0 && read(fd, input, sizeof(input)) == -1 && errno == EIO,
            "overrun reported without stale samples");
    require(ioctl(fd, DSP_RESET) == 0 && read(fd, input, 4) == -1 && errno == EAGAIN &&
                poll(&event, 1, 2000) == 1 && (event.revents & POLLIN) &&
                read(fd, input, sizeof(input)) >= 4096,
            "recovered capture after reset");
    require(ioctl(fd, DSP_RESET) == 0 && close(fd) == 0, "reset capture");
    printf("PCM_CAPTURE_PASS samples=%u stereo_pairs=%u transitions=%u\n", samples, pairs,
           transitions);
}

int main(void) {
    struct stat st;
    if (access("/no-audio", F_OK) == 0) {
        require(stat("/dev/dsp", &st) == -1 && errno == ENOENT, "no device without codec");
        puts("PCM_ABSENT_PASS");
    } else {
        require(stat("/dev/dsp", &st) == 0 && S_ISCHR(st.st_mode) && major(st.st_rdev) == 14 &&
                    minor(st.st_rdev) == 3 && (st.st_mode & 0777) == 0660 && st.st_gid == 29,
                "dsp device metadata");
        pid_t child = fork();
        require(child >= 0, "permission test fork");
        if (!child) {
            require(setgid(65534) == 0 && setuid(65534) == 0, "unprivileged credentials");
            _Exit(open("/dev/dsp", O_RDONLY) == -1 && errno == EACCES ? 0 : 1);
        }
        int status;
        require(waitpid(child, &status, 0) == child && status == 0, "microphone permission");
        child = fork();
        require(child >= 0, "audio group test fork");
        if (!child) {
            if (setgid(29) || setuid(65534))
                _Exit(1);
            int fd = open("/dev/dsp", O_WRONLY);
            _Exit(fd >= 0 && close(fd) == 0 ? 0 : 1);
        }
        require(waitpid(child, &status, 0) == child && status == 0, "audio group access");
        if (access("/capture", F_OK) == 0)
            capture();
        else
            playback();
    }
    fflush(NULL);
    reboot(RB_POWER_OFF);
    return 0;
}
