// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/drivers/audio/alsa_pcm.cpp
 * @brief   Linux ALSA playback ABI for Intel HD Audio.
 * @author  frankischilling
 * @date    2026-11-22
 *
 * Handles card discovery, playback stream state, and interleaved PCM writes.
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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
 * Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://gnu.org/licenses/>.
 */
#include "drivers/audio/alsa_pcm.hpp"
#include "core/time.hpp"
#include "drivers/audio/pcm.hpp"
#include "process/task.hpp"

namespace ax::Alsa {
namespace {
// Linux x86-64 ALSA UAPI. All fields that cross the boundary have fixed widths.
struct CardInfo {
    int32_t card, pad;
    char id[16], driver[16], name[32], long_name[80], reserved[16], mixer[80], components[128];
};

struct PcmInfo {
    uint32_t device, subdevice;
    int32_t stream, card;
    char id[64], name[80], subname[32];
    int32_t device_class, subclass;
    uint32_t subdevices, available;
    uint8_t reserved[80];
};

struct ElementList {
    uint32_t offset, space, used, count;
    uint64_t ids;
    uint8_t reserved[56];
};

struct Interval {
    uint32_t min, max, flags;

    bool contains(uint32_t value) const {
        return !(flags & 8) && value >= min && value <= max && (value != min || !(flags & 1)) &&
               (value != max || !(flags & 2));
    }
};

struct HardwareParams {
    uint32_t flags, masks[8][8];
    Interval intervals[21];
    uint32_t requested, changed, info, significant_bits, rate_num, rate_den;
    uint64_t fifo_size;
    uint8_t sync[16], reserved[48];
};

struct SoftwareParams {
    int32_t timestamp_mode;
    uint32_t period_step, sleep_min, pad;
    uint64_t avail_min, alignment, start_threshold, stop_threshold, silence_threshold, silence_size,
        boundary;
    uint32_t version, timestamp_type;
    uint8_t reserved[56];
};

struct Time {
    int64_t seconds, nanos;
};

enum class State : int32_t { open, setup, prepared, running, xrun, draining };

struct Status {
    State state;
    int32_t pad;
    Time trigger, timestamp;
    uint64_t application, hardware;
    int64_t delay;
    uint64_t avail, avail_max, overrange;
    State suspended;
    uint32_t audio_timestamp_data;
    Time audio_timestamp, driver_timestamp;
    uint32_t audio_timestamp_accuracy;
    uint8_t reserved[20];
};

struct Sync {
    uint32_t flags, pad;
    State state;
    int32_t status_pad;
    uint64_t hardware;
    Time timestamp;
    State suspended;
    uint32_t timestamp_pad;
    Time audio_timestamp;
    uint8_t status_reserved[8];
    uint64_t application, avail_min;
    uint8_t control_reserved[48];
};

struct Transfer {
    int64_t result;
    uint64_t address, frames;
};

static_assert(sizeof(CardInfo) == 376 && sizeof(PcmInfo) == 288 && sizeof(ElementList) == 80);
static_assert(sizeof(HardwareParams) == 608 && sizeof(SoftwareParams) == 136);
static_assert(sizeof(Status) == 152 && sizeof(Sync) == 136 && sizeof(Transfer) == 24);

constexpr uint32_t pcm_version = 0x0002000b, control_version = 0x00020008;
constexpr unsigned rate = 48000, channels = 2, sample_bits = 16;
constexpr unsigned frame_bytes = channels * sample_bits / 8;
constexpr unsigned period_frames = Pcm::output_period_bytes / frame_bytes;
constexpr unsigned buffer_frames = Pcm::output_periods * period_frames;
constexpr int again = -11, fault = -14, invalid = -22, xrun = -32, bad_state = -77;

struct Stream {
    State state = State::open;
    SoftwareParams software{};
    uint64_t written = 0, played = 0, max_available = 0;
    Time trigger{};
};

Stream playback;

template <typename T> bool input(Task& task, uint64_t address, T& result) {
    return task.memory->space.copy_in(&result, address, sizeof(result));
}

template <typename T> int output(Task& task, uint64_t address, const T& result) {
    return task.memory->space.copy_out(address, &result, sizeof(result)) ? 0 : fault;
}

PcmInfo info(unsigned available) {
    return {0, 0, 0, 0, "HDA", "HD Audio Playback", "subdevice #0", 0, 0, 1, available, {}};
}

Time now() {
    const auto time = playback.software.timestamp_type ? ticks : clock_realtime_ticks();
    return {int64_t(time / 100), int64_t(time % 100) * 10000000};
}

uint64_t pointer(uint64_t frames) {
    const auto boundary = playback.software.boundary;
    return boundary ? frames % boundary : 0;
}

void default_software() {
    playback.software = {};
    auto& parameters = playback.software;
    parameters.avail_min = period_frames;
    parameters.start_threshold = period_frames;
    parameters.stop_threshold = buffer_frames;
    parameters.boundary = buffer_frames;
    while (parameters.boundary <= ((uint64_t(INT64_MAX) - buffer_frames) / 2))
        parameters.boundary *= 2;
}

int reset(State state) {
    const int result = Pcm::reset_output();
    if (result)
        return result;
    playback.state = state;
    playback.written = playback.played = playback.max_available = 0;
    playback.trigger = {};
    return 0;
}

Pcm::OutputState refresh() {
    const auto device = Pcm::output_state();
    if (playback.state == State::draining)
        drain_status();
    if (playback.state == State::running || playback.state == State::draining) {
        const auto pending = min(playback.written, uint64_t(device.queued / frame_bytes));
        playback.played = max(playback.played, playback.written - pending);
        if (device.fault || (playback.state == State::running && !device.running))
            playback.state = State::xrun;
    }
    playback.max_available = max(playback.max_available, uint64_t(device.space / frame_bytes));
    return device;
}

int start() {
    const int result = Pcm::start_output();
    if (!result) {
        playback.state = State::running;
        playback.trigger = now();
    }
    return result;
}

int hardware_params(Task& task, uint64_t argument, bool configure) {
    HardwareParams parameters{};
    if (!input(task, argument, parameters))
        return fault;
    // Interleaved writes, signed 16-bit little-endian, standard subformat.
    constexpr uint32_t masks[] = {1u << 3, 1u << 2, 1u};
    constexpr uint32_t intervals[] = {sample_bits,
                                      frame_bytes * 8,
                                      channels,
                                      rate,
                                      period_frames * 1000000ull / rate,
                                      period_frames,
                                      Pcm::output_period_bytes,
                                      Pcm::output_periods,
                                      buffer_frames * 1000000ull / rate,
                                      buffer_frames,
                                      buffer_frames * frame_bytes,
                                      0};
    if (parameters.flags & 6) // No exported buffer or period-wakeup suppression.
        return invalid;
    parameters.changed = 0;
    for (unsigned i = 0; i < 3; ++i) {
        if (!(parameters.masks[i][0] & masks[i]))
            return invalid;
        for (unsigned word = 0; word < 8; ++word) {
            const auto bit = word == 0 ? masks[i] : 0;
            if (parameters.masks[i][word] != bit)
                parameters.changed |= 1u << i;
            parameters.masks[i][word] = bit;
        }
    }
    for (unsigned i = 0; i < sizeof(intervals) / sizeof(intervals[0]); ++i) {
        auto& interval = parameters.intervals[i];
        const auto value = intervals[i];
        if (!interval.contains(value))
            return invalid;
        if (interval.min != value || interval.max != value || interval.flags != 4)
            parameters.changed |= 1u << (8 + i);
        interval = {value, value, 4};
    }
    parameters.requested = 0;
    // The shared DMA engine pads and flushes the tail itself.
    parameters.info = 0x100 | 0x40; // INTERLEAVED | PERFECT_DRAIN
    parameters.significant_bits = sample_bits;
    parameters.rate_num = rate;
    parameters.rate_den = 1;
    parameters.fifo_size = 0;
    memset(parameters.sync, 0, sizeof(parameters.sync));
    if (configure && playback.state != State::open && playback.state != State::setup &&
        playback.state != State::prepared)
        return -16;
    const int result = output(task, argument, parameters);
    if (result || !configure)
        return result;
    default_software();
    return reset(State::setup);
}

int software_params(Task& task, uint64_t argument) {
    if (playback.state == State::open)
        return bad_state;
    SoftwareParams parameters{};
    if (!input(task, argument, parameters))
        return fault;
    // A start threshold larger than the ring leaves start under caller control.
    if (!parameters.avail_min || parameters.avail_min > buffer_frames ||
        parameters.stop_threshold > playback.software.boundary || parameters.timestamp_mode < 0 ||
        parameters.timestamp_mode > 1 || parameters.timestamp_type > 2 ||
        parameters.silence_threshold || parameters.silence_size)
        return invalid;
    parameters.boundary = playback.software.boundary;
    const int result = output(task, argument, parameters);
    if (!result)
        playback.software = parameters;
    return result;
}

int status(Task& task, uint64_t argument) {
    const auto device = refresh();
    Status result{};
    result.state = playback.state;
    result.trigger = playback.trigger;
    if (playback.software.timestamp_mode)
        result.timestamp = now();
    result.hardware = pointer(playback.played);
    result.application = pointer(playback.written);
    result.delay = playback.written - playback.played;
    result.avail = device.space / frame_bytes;
    result.avail_max = playback.max_available;
    const int error = output(task, argument, result);
    if (!error)
        playback.max_available = result.avail;
    return error;
}

int synchronize(Task& task, uint64_t argument) {
    Sync requested{};
    if (!input(task, argument, requested))
        return fault;
    if (requested.flags & ~7u)
        return invalid;
    refresh();
    if (!(requested.flags & 2) && requested.application != pointer(playback.written))
        return invalid;
    const auto avail_min = requested.flags & 4 ? playback.software.avail_min : requested.avail_min;
    if (!avail_min || avail_min > buffer_frames)
        return invalid;
    Sync result{};
    result.flags = requested.flags;
    result.state = playback.state;
    result.hardware = pointer(playback.played);
    if (playback.software.timestamp_mode)
        result.timestamp = now();
    result.application = pointer(playback.written);
    result.avail_min = avail_min;
    const int error = output(task, argument, result);
    if (!error)
        playback.software.avail_min = avail_min;
    return error;
}

int64_t write_frames(Task& task, uint64_t argument) {
    Transfer transfer{};
    if (!input(task, argument, transfer) || output(task, argument, int64_t(0)))
        return fault;
    const auto device = refresh();
    const auto frames = min(transfer.frames, uint64_t(device.space / frame_bytes));
    int64_t result;
    if (playback.state == State::xrun)
        result = xrun;
    else if (playback.state != State::prepared && playback.state != State::running)
        result = bad_state;
    else if (!transfer.frames)
        result = 0;
    else if (!frames)
        result = again;
    else {
        uint8_t samples[Pcm::output_period_bytes];
        uint64_t done = 0;
        result = 0;
        while (done < frames) {
            const auto offset = done * frame_bytes;
            const auto count = min(frames - done, uint64_t(period_frames));
            const auto length = count * frame_bytes;
            if (transfer.address > UINT64_MAX - offset ||
                !task.memory->space.copy_in(samples, transfer.address + offset, length)) {
                result = fault;
                break;
            }
            const auto bytes = write(samples, length);
            if (bytes <= 0) {
                result = bytes;
                break;
            }
            done += bytes / frame_bytes;
        }
        if (done)
            result = int64_t(done);
    }
    const int error = output(task, argument, result);
    return error ? error : min(result, int64_t(0));
}

int start_drain() {
    if (playback.state == State::setup)
        return 0;
    if (playback.state == State::xrun)
        return reset(State::setup);
    if (playback.state != State::prepared && playback.state != State::running &&
        playback.state != State::draining)
        return bad_state;
    if (playback.state != State::draining) {
        playback.state = State::draining;
        const int result = Pcm::drain_output();
        if (result && result != again) {
            playback.state = State::xrun;
            return result;
        }
    }
    return drain_status();
}
} // namespace

int open() {
    const int result = Pcm::open_output();
    if (!result) {
        playback = {};
        default_software();
    }
    return result;
}

void close() {
    Pcm::close_output();
    playback = {};
}

bool ready() {
    const auto device = refresh();
    return playback.state == State::xrun ||
           ((playback.state == State::prepared || playback.state == State::running) &&
            device.space / frame_bytes >= playback.software.avail_min);
}

bool transfer_ready() {
    const auto device = refresh();
    return (playback.state != State::prepared && playback.state != State::running) ||
           device.space >= frame_bytes;
}

int64_t write(const void* buffer, size_t length) {
    refresh();
    if (playback.state == State::xrun)
        return xrun;
    if (playback.state != State::prepared && playback.state != State::running)
        return bad_state;
    if (length % frame_bytes)
        return invalid;
    if (!length)
        return 0;
    const auto result = Pcm::queue_output(buffer, length);
    if (result <= 0)
        return result;
    playback.written += result / frame_bytes;
    if (playback.state == State::prepared &&
        playback.written >= max(uint64_t(period_frames), playback.software.start_threshold)) {
        if (const int error = start())
            return error;
    }
    return result;
}

int drain_status() {
    if (playback.state != State::draining)
        return playback.state == State::setup ? 0 : bad_state;
    const int result = Pcm::drain_status();
    if (result != again) {
        playback.state = result ? State::xrun : State::setup;
        if (!result)
            playback.played = playback.written;
    }
    return result;
}

int64_t control_ioctl(uint64_t request, uint64_t argument) {
    auto& task = *current_task();
    switch (request) {
    case 0x80045500:
        return output(task, argument, control_version);
    case 0x81785501: {
        constexpr CardInfo card{0,  0,  "AxiomHDA", "HDA", "HD Audio", "Axiom64 HD Audio Playback",
                                {}, {}, {}};
        return output(task, argument, card);
    }
    case 0xc0505510: {
        ElementList list{};
        if (!input(task, argument, list))
            return fault;
        list.used = list.count = 0;
        return output(task, argument, list);
    }
    case 0x80045530: {
        int32_t device;
        if (!input(task, argument, device))
            return fault;
        return output(task, argument, device < 0 ? 0 : -1);
    }
    case 0xc1205531: {
        PcmInfo requested{};
        if (!input(task, argument, requested))
            return fault;
        if (requested.stream || requested.device || requested.subdevice)
            return -19;
        return output(task, argument, info(!Pcm::output_busy()));
    }
    case 0x40045532: {
        int32_t subdevice;
        if (!input(task, argument, subdevice))
            return fault;
        return subdevice == -1 || subdevice == 0 ? 0 : invalid;
    }
    default:
        return -25;
    }
}

int64_t playback_ioctl(Task& task, uint64_t request, uint64_t argument) {
    switch (request) {
    case 0x80044100:
        return output(task, argument, pcm_version);
    case 0x81204101:
        return output(task, argument, info(0));
    case 0x40044102:
    case 0x40044103:
    case 0x40044104: {
        int32_t value;
        if (!input(task, argument, value))
            return fault;
        if (request == 0x40044104)
            return 0;
        if (value < 0 || value > (request == 0x40044102 ? 1 : 2))
            return invalid;
        if (request == 0x40044102)
            playback.software.timestamp_mode = value;
        else
            playback.software.timestamp_type = value;
        return 0;
    }
    case 0xc2604110:
        return hardware_params(task, argument, false);
    case 0xc2604111:
        return hardware_params(task, argument, true);
    case 0x4112: // HW_FREE
        if (playback.state == State::running || playback.state == State::draining)
            return -16;
        return reset(State::open);
    case 0xc0884113:
        return software_params(task, argument);
    case 0x80984120:
    case 0xc0984124:
        return status(task, argument);
    case 0x80084121: {
        refresh();
        if (playback.state == State::xrun)
            return xrun;
        return output(task, argument, int64_t(playback.written - playback.played));
    }
    case 0x4122: // HWSYNC
        refresh();
        return playback.state == State::xrun ? xrun : 0;
    case 0xc0884123:
        return synchronize(task, argument);
    case 0x4140: // PREPARE
        return playback.state == State::open || playback.state == State::draining
                   ? bad_state
                   : reset(State::prepared);
    case 0x4142: // START
        return playback.state == State::prepared ? start() : bad_state;
    case 0x4143: // DROP
        return playback.state == State::open ? bad_state : reset(State::setup);
    case drain_request:
        return start_drain();
    case write_frames_request:
        return write_frames(task, argument);
    default:
        return -25;
    }
}
} // namespace ax::Alsa
