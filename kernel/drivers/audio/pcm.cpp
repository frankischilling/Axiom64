// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/drivers/audio/pcm.cpp
 * @brief   PCM device over the Intel HD Audio DMA rings.
 * @author  frankischilling
 * @date    2026-11-21
 *
 * Manages PCM direction ownership, streaming buffers, and OSS controls.
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
#include "drivers/audio/pcm.hpp"
#include "core/time.hpp"
#include "drivers/audio/hda.hpp"
#include "mm/dma.hpp"
#include "process/task.hpp"

namespace ax::Pcm {
namespace {
using Hda::Direction;
constexpr unsigned periods = 16, period_bytes = page_size, buffer_bytes = periods * period_bytes;
constexpr unsigned default_rate = 48000, default_channels = 2, signed_16_le = 0x10;
constexpr unsigned output_limit = periods - 2;
constexpr int again = -11, io_error = -5;

struct Channel {
    Direction direction;
    uint64_t dma = 0, activity = 0;
    unsigned rate = default_rate, channels = default_channels;
    unsigned head = 0, tail = 0, hardware_period = 0, count = 0, partial = 0;
    bool opened = false, running = false, fault = false, unsafe = false;

    uint8_t* slot(unsigned index) const {
        return static_cast<uint8_t*>(physical(dma + (1 + index) * page_size));
    }

    bool supported() const {
        return dma && Hda::available(direction);
    }

    unsigned next(unsigned index) const {
        return (index + 1) % periods;
    }

    void clear() {
        head = tail = count = partial = hardware_period = 0;
    }

    bool stop() {
        if (running && !Hda::run(direction, false)) {
            fault = unsafe = true;
            return false;
        }
        running = false;
        return true;
    }

    bool start() {
        if (fault || !Hda::prepare(direction, rate, channels, dma, periods, buffer_bytes) ||
            !Hda::run(direction, true)) {
            fault = true;
            unsafe = !Hda::run(direction, false);
            return false;
        }
        hardware_period = 0;
        activity = ticks;
        running = true;
        return true;
    }

    void reset() {
        if (!stop() || unsafe)
            return;
        clear();
        fault = false;
        memset(slot(0), 0, buffer_bytes);
    }

    void fail() {
        stop();
        fault = true;
    }

    void update() {
        if (!running || fault)
            return;
        const unsigned position = Hda::position(direction);
        const uint64_t elapsed = ticks - activity;
        // A complete unobserved turn of the cyclic buffer makes ownership ambiguous.
        const auto duration = buffer_bytes * 100u / (rate * channels * 2);
        const bool hardware_error = Hda::failed(direction);
        if (position >= buffer_bytes || elapsed >= duration || hardware_error) {
            log("hda: DMA fault capture=%u position=%u elapsed_ticks=%u device_error=%u\n",
                uint64_t(direction == Direction::capture), uint64_t(position), elapsed,
                uint64_t(hardware_error));
            fail();
            return;
        }
        activity = ticks;
        const unsigned index = position / period_bytes;
        const unsigned completed = (index + periods - hardware_period) % periods;
        if (!completed)
            return;
        asm volatile("mfence" ::: "memory");
        if (direction == Direction::capture) {
            // Keep one period between hardware and the oldest unread capture.
            if (count + completed >= periods - 1) {
                log("hda: capture overrun queued=%u completed=%u\n", uint64_t(count),
                    uint64_t(completed));
                fail();
                return;
            }
            count += completed;
        } else {
            for (unsigned i = 0; i < min(completed, count); ++i) {
                memset(slot(head), 0, period_bytes);
                head = next(head);
            }
            count -= min(completed, count);
            if (!count) {
                if (stop())
                    head = tail = hardware_period = 0;
                return;
            }
        }
        hardware_period = index;
    }
};

Channel playback{Direction::playback}, capture{Direction::capture};
Channel* const channels[] = {&playback, &capture};
uint8_t staged[period_bytes];
uint64_t drain_started;
bool draining, fence_pending, closing;

bool writable(const Handle& handle) {
    return (handle.flags & 3) != 0;
}

bool readable(const Handle& handle) {
    return (handle.flags & 3) != 1;
}

bool allocate(Channel& channel) {
    if (!Hda::supports(channel.direction, default_rate, default_channels))
        return false;
    channel.dma = Dma::allocate(1 + periods, Dma::pci);
    if (!channel.dma)
        return false;
    auto* descriptors = static_cast<Hda::BufferDescriptor*>(physical(channel.dma));
    for (unsigned i = 0; i < periods; ++i)
        descriptors[i] = {channel.dma + (i + 1) * page_size, period_bytes, 0};
    return true;
}

bool output_space() {
    // Leave a whole queued period between the hardware and the next DMA write.
    return playback.count < output_limit && (!playback.running || playback.count >= 2);
}

void append_period(const void* data, size_t length) {
    auto* slot = playback.slot(playback.tail);
    if (length)
        memcpy(slot, data, length);
    if (length < period_bytes)
        memset(slot + length, 0, period_bytes - length);
    playback.tail = playback.next(playback.tail);
    ++playback.count;
}

void service_output() {
    playback.update();
    if (!draining)
        return;
    if (ticks - drain_started >= 500 && !playback.fault)
        playback.fail();
    if (!playback.fault && fence_pending && output_space() && playback.count <= output_limit - 3) {
        if (playback.partial) {
            append_period(staged, playback.partial);
            playback.partial = 0;
        }
        // Let the codec deliver the last PCM samples after the link consumed them.
        append_period(nullptr, 0);
        append_period(nullptr, 0);
        asm volatile("mfence" ::: "memory");
        if (!playback.running)
            playback.start();
        fence_pending = false;
    }
    if (playback.fault || (!fence_pending && !playback.count)) {
        draining = false;
        if (closing) {
            playback.reset();
            closing = false;
        }
    }
}

int begin_drain() {
    service_output();
    if (playback.fault)
        return io_error;
    if (!draining && (playback.partial || playback.count)) {
        drain_started = ticks;
        draining = fence_pending = true;
        service_output();
    }
    return playback.fault ? io_error : draining ? again : 0;
}

template <typename T> int copy_result(uint64_t address, const T& result) {
    return current_task()->memory->space.copy_out(address, &result, sizeof(result)) ? 0 : -14;
}

unsigned parameter(const Handle& handle, int requested, bool rate) {
    auto& first = writable(handle) ? playback : capture;
    const unsigned old = rate ? first.rate : first.channels;
    const unsigned choices[] = {11025, 22050, 32000, 44100, 48000};
    if (requested <= 0)
        return old;
    unsigned best = old, distance = UINT32_MAX;
    for (unsigned index = 0; index < (rate ? 5u : 2u); ++index) {
        const unsigned candidate = rate ? choices[index] : index + 1;
        if ((!writable(handle) ||
             Hda::supports(Direction::playback, rate ? candidate : playback.rate,
                           rate ? playback.channels : candidate)) &&
            (!readable(handle) || Hda::supports(Direction::capture, rate ? candidate : capture.rate,
                                                rate ? capture.channels : candidate))) {
            const auto value = unsigned(requested);
            const auto delta = value > candidate ? value - candidate : candidate - value;
            if (delta < distance) {
                best = candidate;
                distance = delta;
            }
        }
    }
    return best;
}
} // namespace

bool initialize() {
    Hda::initialize();
    const bool output = allocate(playback);
    const bool input = allocate(capture);
    return output || input;
}

int open(const Handle& handle) {
    if ((handle.flags & 3) == 3)
        return -22;
    if ((readable(handle) && (!capture.supported() || capture.unsafe)) ||
        (writable(handle) && (!playback.supported() || playback.unsafe)))
        return -19;
    if ((readable(handle) && capture.opened) || (writable(handle) && (playback.opened || closing)))
        return -16;
    for (auto* channel : channels) {
        if (channel == &playback ? writable(handle) : readable(handle)) {
            channel->rate = default_rate;
            channel->channels = default_channels;
            channel->reset();
            channel->opened = true;
        }
    }
    return 0;
}

void close(const Handle& handle) {
    if (writable(handle)) {
        playback.opened = false;
        if (!(handle.flags & 04000) && begin_drain() == again) {
            closing = true;
        } else {
            draining = false;
            playback.reset();
        }
    }
    if (readable(handle)) {
        capture.reset();
        capture.opened = false;
    }
}

bool ready(const Handle& handle, bool write) {
    if (write && writable(handle)) {
        service_output();
        return playback.fault || (!draining && output_space());
    }
    if (!write && readable(handle)) {
        if (!capture.running && !capture.fault)
            capture.start();
        capture.update();
        return capture.fault || capture.count;
    }
    return false;
}

int64_t read(void* buffer, size_t length) {
    if (!capture.running && !capture.start())
        return io_error;
    capture.update();
    if (capture.fault)
        return io_error;
    if (!capture.count)
        return again;
    auto* result = static_cast<uint8_t*>(buffer);
    const auto bytes = min(length, size_t(capture.count * period_bytes - capture.partial));
    size_t done = 0;
    while (done < bytes) {
        const auto amount = min(bytes - done, size_t(period_bytes - capture.partial));
        memcpy(result + done, capture.slot(capture.head) + capture.partial, amount);
        done += amount;
        capture.partial += amount;
        if (capture.partial == period_bytes) {
            capture.partial = 0;
            capture.head = capture.next(capture.head);
            --capture.count;
        }
    }
    return done;
}

int64_t write(const void* buffer, size_t length) {
    service_output();
    if (playback.fault)
        return io_error;
    if (draining || !output_space())
        return again;
    const auto* source = static_cast<const uint8_t*>(buffer);
    const auto bytes =
        min(length, size_t((output_limit - playback.count) * period_bytes - playback.partial));
    size_t done = 0;
    while (done < bytes) {
        const auto amount = min(bytes - done, size_t(period_bytes - playback.partial));
        memcpy(staged + playback.partial, source + done, amount);
        done += amount;
        playback.partial += amount;
        if (playback.partial == period_bytes) {
            append_period(staged, period_bytes);
            playback.partial = 0;
        }
    }
    asm volatile("mfence" ::: "memory");
    if (!playback.running && playback.count && !playback.start())
        return io_error;
    return done ? int64_t(done) : again;
}

int64_t ioctl(const Handle& handle, uint64_t request, uint64_t argument) {
    switch (request) {
    case 0x5000: // SNDCTL_DSP_RESET
        if (writable(handle)) {
            draining = false;
            playback.reset();
        }
        if (readable(handle))
            capture.reset();
        return ((writable(handle) && playback.unsafe) || (readable(handle) && capture.unsafe))
                   ? io_error
                   : 0;
    case sync_request:
        return writable(handle) ? begin_drain() : 0;
    case 0xc0045002:   // SNDCTL_DSP_SPEED
    case 0xc0045005:   // SNDCTL_DSP_SETFMT
    case 0xc0045006: { // SNDCTL_DSP_CHANNELS
        int value;
        if (!current_task()->memory->space.copy_in(&value, argument, sizeof(value)))
            return -14;
        if (request == 0xc0045005)
            return copy_result(argument, int(signed_16_le));
        const bool rate = request == 0xc0045002;
        const int selected = parameter(handle, value, rate);
        if (int error = copy_result(argument, selected))
            return error;
        for (auto* channel : channels) {
            if (channel == &playback ? !writable(handle) : !readable(handle))
                continue;
            auto& property = rate ? channel->rate : channel->channels;
            if (selected != int(property)) {
                if (channel == &playback)
                    draining = false;
                channel->reset();
                if (channel->unsafe)
                    return io_error;
                property = selected;
            }
        }
        return 0;
    }
    case 0xc0045004: // SNDCTL_DSP_GETBLKSIZE
        return copy_result(argument, int(period_bytes));
    case 0x8004500b: // SNDCTL_DSP_GETFMTS
        return copy_result(argument, int(signed_16_le));
    case 0x8010500c:   // SNDCTL_DSP_GETOSPACE
    case 0x8010500d: { // SNDCTL_DSP_GETISPACE
        const bool output = request == 0x8010500c;
        if (output ? !writable(handle) : !readable(handle))
            return -22;
        auto& channel = output ? playback : capture;
        if (output)
            service_output();
        else
            channel.update();
        if (channel.fault)
            return io_error;
        const unsigned fragments = output ? output_limit - channel.count : channel.count;
        const int bytes = output && (draining || !output_space())
                              ? 0
                              : fragments * period_bytes - channel.partial;
        const int result[] = {bytes / int(period_bytes), int(output ? output_limit : periods - 2),
                              int(period_bytes), bytes};
        return copy_result(argument, result);
    }
    case 0x8004500f: // SNDCTL_DSP_GETCAPS
        return copy_result(argument, int(playback.supported() && capture.supported() ? 0x100 : 0));
    case 0x5016: // SNDCTL_DSP_SETDUPLEX
        return readable(handle) && writable(handle) ? 0 : -22;
    default:
        return -25;
    }
}

int drain_status() {
    service_output();
    return playback.fault ? io_error : draining ? again : 0;
}

void poll() {
    service_output();
    capture.update();
}

void shutdown() {
    playback.stop();
    capture.stop();
    Hda::shutdown();
}
} // namespace ax::Pcm
