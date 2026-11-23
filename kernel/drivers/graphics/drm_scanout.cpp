// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/drivers/graphics/drm_scanout.cpp
 * @brief   Linux DRM legacy modesetting for a fixed scanout.
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
#include "drivers/graphics/drm_scanout.hpp"
#include "boot/boot.hpp"
#include "drivers/graphics/virtio_gpu.hpp"
#include "fs/vfs.hpp"
#include "process/task.hpp"

namespace ax {
namespace {
// These layouts follow the Linux x86-64 DRM UAPI in drm.h and drm_mode.h.
struct Version {
    int32_t major, minor, patch;
    uint64_t name_len, name, date_len, date, description_len, description;
};

struct Cap {
    uint64_t capability, value;
};

struct Mode {
    uint32_t clock;
    uint16_t width, hsync_start, hsync_end, htotal, hskew;
    uint16_t height, vsync_start, vsync_end, vtotal, vscan;
    uint32_t refresh, flags, type;
    char name[32];
};

struct Resources {
    uint64_t fbs, crtcs, connectors, encoders;
    uint32_t fb_count, crtc_count, connector_count, encoder_count;
    uint32_t min_width, max_width, min_height, max_height;
};

struct Crtc {
    uint64_t connectors;
    uint32_t connector_count, id, fb, x, y, gamma_size, mode_valid;
    Mode mode;
};

struct Encoder {
    uint32_t id, type, crtc, possible_crtcs, possible_clones;
};

struct Connector {
    uint64_t encoders, modes, properties, property_values;
    uint32_t mode_count, property_count, encoder_count, encoder, id, type, type_id;
    uint32_t connection, width_mm, height_mm, subpixel, pad;
};

struct Dumb {
    uint32_t height, width, bpp, flags, handle, pitch;
    uint64_t size;
};

struct MapDumb {
    uint32_t handle, pad;
    uint64_t offset;
};

struct GemClose {
    uint32_t handle, pad;
};

struct AddFb {
    uint32_t id, width, height, format, flags;
    uint32_t handles[4], pitches[4], offsets[4];
    uint64_t modifiers[4];
};

struct DirtyFb {
    uint32_t id, flags, color, clip_count;
    uint64_t clips;
};

struct Clip {
    uint16_t x1, y1, x2, y2;
};

static_assert(sizeof(Version) == 64 && sizeof(Cap) == 16 && sizeof(Mode) == 68);
static_assert(sizeof(Resources) == 64 && sizeof(Crtc) == 104 && sizeof(Encoder) == 20);
static_assert(sizeof(Connector) == 80 && sizeof(Dumb) == 32 && sizeof(MapDumb) == 16);
static_assert(sizeof(GemClose) == 8 && sizeof(AddFb) == 104);
static_assert(sizeof(DirtyFb) == 24 && sizeof(Clip) == 8);

template <class T> constexpr uint64_t read_write(unsigned number) {
    return 0xc0006400 | (sizeof(T) << 16) | number;
}

constexpr uint32_t crtc_id = 1, encoder_id = 2, connector_id = 3;
constexpr uint32_t xrgb8888 = 0x34325258; // DRM_FORMAT_XRGB8888
constexpr uint64_t max_buffer_size = 64 * 1024 * 1024;
constexpr uint64_t max_live_bytes = 2 * max_buffer_size;
constexpr uint64_t map_stride = max_buffer_size;
constexpr unsigned object_limit = 16;
constexpr unsigned max_clips = 256;

struct Buffer {
    uint64_t address, size;
    uint32_t id;
    unsigned references;
};

struct ScanoutBuffer {
    Buffer* buffer;
    uint32_t id, pitch, offset;
};
} // namespace

struct DrmFile {
    Buffer* buffers[object_limit];
    ScanoutBuffer framebuffers[object_limit];
    bool was_master;
};

namespace DrmScanout {
namespace {
const BootFramebuffer* screen;
bool virtio_backend;
Mode mode;
DrmFile* master;
ScanoutBuffer* active;
uint64_t live_bytes;
uint32_t next_id = connector_id + 1;

template <class T> bool read(uint64_t address, T& value) {
    return current_task()->memory->space.copy_in(&value, address, sizeof(value));
}

template <class T> bool write(uint64_t address, const T& value) {
    return current_task()->memory->space.copy_out(address, &value, sizeof(value));
}

bool string_out(uint64_t address, uint64_t& length, const char* text) {
    auto size = strlen(text);
    auto copied = min(size, length);
    length = size;
    return !address || !copied || current_task()->memory->space.copy_out(address, text, copied);
}

void release_buffer(Buffer* buffer) {
    if (--buffer->references)
        return;
    page_free(buffer->address, buffer->size / page_size);
    live_bytes -= buffer->size;
    release(buffer);
}

Buffer** find_handle(DrmFile& file, uint32_t id) {
    for (auto& buffer : file.buffers)
        if (buffer && buffer->id == id)
            return &buffer;
    return nullptr;
}

ScanoutBuffer* find_framebuffer(DrmFile& file, uint32_t id) {
    for (auto& fb : file.framebuffers)
        if (fb.buffer && fb.id == id)
            return &fb;
    return nullptr;
}

bool refresh() {
    return !virtio_backend || virtio_gpu_request_refresh();
}

void copy_pixels(const ScanoutBuffer& fb, const Clip& clip) {
    auto* destination = static_cast<uint8_t*>(screen->address) + clip.x1 * sizeof(uint32_t);
    const auto* source = static_cast<const uint8_t*>(physical(fb.buffer->address)) + fb.offset +
                         clip.x1 * sizeof(uint32_t);
    auto row_bytes = (clip.x2 - clip.x1) * sizeof(uint32_t);
    for (unsigned row = clip.y1; row < clip.y2; ++row)
        memcpy(destination + row * screen->pitch, source + row * fb.pitch, row_bytes);
}

bool set_scanout(ScanoutBuffer* fb) {
    if (!refresh())
        return false;
    if (fb) {
        copy_pixels(*fb, {0, 0, mode.width, mode.height});
    } else {
        auto* destination = static_cast<uint8_t*>(screen->address);
        auto row_bytes = screen->width * sizeof(uint32_t);
        for (size_t row = 0; row < screen->height; ++row)
            memset(destination + row * screen->pitch, 0, row_bytes);
    }
    active = fb;
    return true;
}

void remove_framebuffer(ScanoutBuffer& fb) {
    if (active == &fb) {
        set_scanout(nullptr);
        active = nullptr;
    }
    release_buffer(fb.buffer);
    fb = {};
}

int64_t version(uint64_t argument) {
    Version value{};
    if (!read(argument, value))
        return -14;
    value.major = 1;
    value.minor = value.patch = 0;
    if (!string_out(value.name, value.name_len, "axiom64-scanout") ||
        !string_out(value.date, value.date_len, "") ||
        !string_out(value.description, value.description_len, "Axiom64 fixed scanout"))
        return -14;
    return write(argument, value) ? 0 : -14;
}

int64_t resources(const DrmFile& file, uint64_t argument) {
    Resources value{};
    if (!read(argument, value))
        return -14;
    uint32_t ids[object_limit];
    uint32_t count = 0;
    for (const auto& fb : file.framebuffers)
        if (fb.buffer)
            ids[count++] = fb.id;
    if (count && value.fb_count >= count &&
        !current_task()->memory->space.copy_out(value.fbs, ids, count * sizeof(ids[0])))
        return -14;
    if ((value.crtc_count && !write(value.crtcs, crtc_id)) ||
        (value.connector_count && !write(value.connectors, connector_id)) ||
        (value.encoder_count && !write(value.encoders, encoder_id)))
        return -14;
    value.fb_count = count;
    value.crtc_count = value.connector_count = value.encoder_count = 1;
    value.min_width = value.max_width = mode.width;
    value.min_height = value.max_height = mode.height;
    return write(argument, value) ? 0 : -14;
}

int64_t connector(uint64_t argument) {
    Connector value{};
    if (!read(argument, value))
        return -14;
    if (value.id != connector_id)
        return -2;
    if ((value.encoder_count && !write(value.encoders, encoder_id)) ||
        (value.mode_count && !write(value.modes, mode)))
        return -14;
    value.type = 15; // DRM_MODE_CONNECTOR_VIRTUAL
    value.type_id = 1;
    value.connection = 1; // DRM_MODE_CONNECTED
    value.encoder = active ? encoder_id : 0;
    value.mode_count = value.encoder_count = 1;
    value.property_count = value.width_mm = value.height_mm = value.pad = 0;
    value.subpixel = 1; // unknown
    return write(argument, value) ? 0 : -14;
}

int64_t encoder(uint64_t argument) {
    Encoder value{};
    if (!read(argument, value))
        return -14;
    if (value.id != encoder_id)
        return -2;
    value = {encoder_id, 5, active ? crtc_id : 0, 1, 0};
    return write(argument, value) ? 0 : -14;
}

int64_t crtc(uint64_t argument) {
    Crtc value{};
    if (!read(argument, value))
        return -14;
    if (value.id != crtc_id)
        return -2;
    value = {};
    value.id = crtc_id;
    if (active) {
        value.fb = active->id;
        value.mode_valid = 1;
        value.mode = mode;
    }
    return write(argument, value) ? 0 : -14;
}

int64_t set_crtc(DrmFile& file, uint64_t argument) {
    if (master != &file)
        return -13;
    Crtc value{};
    if (!read(argument, value))
        return -14;
    if (value.id != crtc_id)
        return -2;
    if (!value.mode_valid && !value.connector_count && !value.fb)
        return set_scanout(nullptr) ? 0 : -5;
    if (!value.mode_valid || value.connector_count != 1 || value.x || value.y ||
        value.mode.width != mode.width || value.mode.height != mode.height ||
        value.mode.clock != mode.clock || value.mode.hsync_start != mode.hsync_start ||
        value.mode.hsync_end != mode.hsync_end || value.mode.htotal != mode.htotal ||
        value.mode.hskew != mode.hskew || value.mode.vsync_start != mode.vsync_start ||
        value.mode.vsync_end != mode.vsync_end || value.mode.vtotal != mode.vtotal ||
        value.mode.vscan != mode.vscan || value.mode.flags != mode.flags)
        return -22;
    uint32_t connected;
    if (!read(value.connectors, connected))
        return -14;
    auto* fb = find_framebuffer(file, value.fb);
    if (!fb || connected != connector_id)
        return -2;
    return set_scanout(fb) ? 0 : -5;
}

int64_t create_dumb(DrmFile& file, uint64_t argument) {
    Dumb value{};
    if (!read(argument, value))
        return -14;
    if (!value.width || value.width > mode.width || !value.height || value.height > mode.height ||
        value.bpp != 32 || value.flags)
        return -22;
    value.pitch = value.width * sizeof(uint32_t);
    value.size = align_up(uint64_t(value.pitch) * value.height);
    if (value.size > max_buffer_size || value.size > max_live_bytes - live_bytes)
        return -12;
    for (auto& handle : file.buffers) {
        if (handle)
            continue;
        if (next_id == UINT32_MAX)
            return -28;
        auto* buffer = static_cast<Buffer*>(alloc(sizeof(Buffer)));
        if (!buffer)
            return -12;
        auto address = page_alloc(value.size / page_size);
        if (!address) {
            release(buffer);
            return -12;
        }
        *buffer = {address, value.size, next_id++, 1};
        live_bytes += value.size;
        value.handle = buffer->id;
        if (!write(argument, value)) {
            release_buffer(buffer);
            return -14;
        }
        handle = buffer;
        return 0;
    }
    return -28;
}

int64_t map_dumb(DrmFile& file, uint64_t argument) {
    MapDumb value{};
    if (!read(argument, value))
        return -14;
    if (value.pad)
        return -22;
    if (!find_handle(file, value.handle))
        return -2;
    value.offset = uint64_t(value.handle) * map_stride;
    return write(argument, value) ? 0 : -14;
}

int64_t add_framebuffer(DrmFile& file, uint64_t argument) {
    AddFb value{};
    if (!read(argument, value))
        return -14;
    if (value.format != xrgb8888 || value.flags || value.modifiers[0] ||
        value.width != mode.width || value.height != mode.height ||
        value.offsets[0] % sizeof(uint32_t) || value.pitches[0] % sizeof(uint32_t) ||
        value.pitches[0] < value.width * sizeof(uint32_t))
        return -22;
    for (unsigned plane = 1; plane < 4; ++plane)
        if (value.handles[plane] || value.pitches[plane] || value.offsets[plane] ||
            value.modifiers[plane])
            return -22;
    auto slot = find_handle(file, value.handles[0]);
    if (!slot)
        return -2;
    auto* buffer = *slot;
    uint64_t end = value.offsets[0] + uint64_t(value.pitches[0]) * (value.height - 1) +
                   uint64_t(value.width) * sizeof(uint32_t);
    if (end > buffer->size)
        return -22;
    for (auto& fb : file.framebuffers) {
        if (fb.buffer)
            continue;
        if (next_id == UINT32_MAX)
            return -28;
        value.id = next_id++;
        if (!write(argument, value))
            return -14;
        ++buffer->references;
        fb = {buffer, value.id, value.pitches[0], value.offsets[0]};
        return 0;
    }
    return -28;
}

int64_t dirty_framebuffer(DrmFile& file, uint64_t argument) {
    if (master != &file)
        return -13;
    DirtyFb value{};
    if (!read(argument, value))
        return -14;
    auto* fb = find_framebuffer(file, value.id);
    if (!fb)
        return -2;
    if (value.flags || value.clip_count > max_clips || bool(value.clips) != bool(value.clip_count))
        return -22;
    Clip damage{0, 0, mode.width, mode.height};
    if (value.clip_count) {
        Clip clips[max_clips];
        if (!current_task()->memory->space.copy_in(clips, value.clips,
                                                   value.clip_count * sizeof(Clip)))
            return -14;
        damage = clips[0];
        for (unsigned i = 0; i < value.clip_count; ++i) {
            const auto& clip = clips[i];
            if (clip.x1 >= clip.x2 || clip.y1 >= clip.y2 || clip.x2 > mode.width ||
                clip.y2 > mode.height)
                return -22;
            damage.x1 = min(damage.x1, clip.x1);
            damage.y1 = min(damage.y1, clip.y1);
            damage.x2 = max(damage.x2, clip.x2);
            damage.y2 = max(damage.y2, clip.y2);
        }
    }
    if (fb != active)
        return 0;
    if (!refresh())
        return -5;
    copy_pixels(*fb, damage);
    return 0;
}

void set_mode_name(char* name, unsigned width, unsigned height) {
    unsigned dimensions[] = {width, height};
    for (unsigned i = 0; i < 2; ++i) {
        char digits[5];
        unsigned length = 0, number = dimensions[i];
        do {
            digits[length++] = '0' + number % 10;
            number /= 10;
        } while (number);
        while (length)
            *name++ = digits[--length];
        if (i == 0)
            *name++ = 'x';
    }
    *name = '\0';
}
} // namespace

bool init(const BootFramebuffer& fb, bool virtio) {
    if (!fb.address || !fb.width || !fb.height || fb.width > UINT16_MAX || fb.height > UINT16_MAX ||
        fb.bpp != 32 || fb.pitch < fb.width * sizeof(uint32_t) ||
        fb.pitch > max_buffer_size / fb.height || fb.red_mask_size != 8 ||
        fb.red_mask_shift != 16 || fb.green_mask_size != 8 || fb.green_mask_shift != 8 ||
        fb.blue_mask_size != 8 || fb.blue_mask_shift != 0)
        return false;
    screen = &fb;
    virtio_backend = virtio;
    // Match the simple-display convention for a mode whose timings are unknown.
    mode.clock = 1;
    mode.width = mode.hsync_start = mode.hsync_end = mode.htotal = fb.width;
    mode.height = mode.vsync_start = mode.vsync_end = mode.vtotal = fb.height;
    mode.type = (1 << 3) | (1 << 6); // preferred, driver
    set_mode_name(mode.name, mode.width, mode.height);
    return true;
}

int open(Handle& handle) {
    auto* file = static_cast<DrmFile*>(alloc(sizeof(DrmFile)));
    if (!file)
        return -12;
    *file = {};
    handle.drm = file;
    if (!master && (handle.flags & 3) == 2) {
        master = file;
        file->was_master = true;
    }
    return 0;
}

void close(Handle& handle) {
    auto& file = *handle.drm;
    for (auto& fb : file.framebuffers)
        if (fb.buffer)
            remove_framebuffer(fb);
    for (auto* buffer : file.buffers)
        if (buffer)
            release_buffer(buffer);
    if (master == &file)
        master = nullptr;
    handle.drm = nullptr;
    release(&file);
}

int64_t ioctl(Handle& handle, uint64_t request, uint64_t argument) {
    if (!handle.drm)
        return -9;
    auto& file = *handle.drm;
    switch (request) {
    case read_write<Version>(0x00):
        return version(argument);
    case read_write<Cap>(0x0c): {
        Cap value{};
        if (!read(argument, value))
            return -14;
        switch (value.capability) {
        case 1: // DRM_CAP_DUMB_BUFFER
            value.value = 1;
            break;
        case 3: // DRM_CAP_DUMB_PREFERRED_DEPTH
            value.value = 24;
            break;
        case 4:    // DRM_CAP_DUMB_PREFER_SHADOW
        case 5:    // DRM_CAP_PRIME
        case 7:    // DRM_CAP_ASYNC_PAGE_FLIP
        case 0x10: // DRM_CAP_ADDFB2_MODIFIERS
        case 0x11: // DRM_CAP_PAGE_FLIP_TARGET
        case 0x13: // DRM_CAP_SYNCOBJ
        case 0x14: // DRM_CAP_SYNCOBJ_TIMELINE
            value.value = 0;
            break;
        default:
            return -22;
        }
        return write(argument, value) ? 0 : -14;
    }
    case read_write<Resources>(0xa0):
        return resources(file, argument);
    case read_write<Crtc>(0xa1):
        return crtc(argument);
    case read_write<Encoder>(0xa6):
        return encoder(argument);
    case read_write<Connector>(0xa7):
        return connector(argument);
    }
    if ((handle.flags & 3) != 2)
        return -13;
    switch (request) {
    case 0x641e: // DRM_IOCTL_SET_MASTER
        if (master == &file)
            return 0;
        if (master ||
            (!file.was_master && !capable(current_task()->credentials, Capability::sys_admin)))
            return -13;
        master = &file;
        file.was_master = true;
        return 0;
    case 0x641f: // DRM_IOCTL_DROP_MASTER
        if (master != &file)
            return -13;
        master = nullptr;
        return 0;
    case read_write<Crtc>(0xa2):
        return set_crtc(file, argument);
    case read_write<DirtyFb>(0xb1):
        return dirty_framebuffer(file, argument);
    case read_write<Dumb>(0xb2):
        return create_dumb(file, argument);
    case read_write<MapDumb>(0xb3):
        return map_dumb(file, argument);
    case 0x40086409:                   // DRM_IOCTL_GEM_CLOSE
    case read_write<uint32_t>(0xb4): { // DRM_IOCTL_MODE_DESTROY_DUMB
        GemClose value{};
        if (request == 0x40086409 ? !read(argument, value) : !read(argument, value.handle))
            return -14;
        auto slot = find_handle(file, value.handle);
        if (!slot)
            return -2;
        release_buffer(*slot);
        *slot = nullptr;
        return 0;
    }
    case read_write<AddFb>(0xb8):
        return add_framebuffer(file, argument);
    case read_write<uint32_t>(0xaf): { // DRM_IOCTL_MODE_RMFB
        uint32_t id;
        if (!read(argument, id))
            return -14;
        auto* fb = find_framebuffer(file, id);
        if (!fb)
            return -2;
        remove_framebuffer(*fb);
        return 0;
    }
    default:
        return -25;
    }
}

int mapping(const Handle& handle, uint64_t offset, size_t size, int prot, int flags,
            uint64_t& address) {
    if (!handle.drm)
        return -9;
    if ((handle.flags & 3) != 2)
        return -13;
    if ((flags & 3) != 1 || (prot & 4))
        return -22;
    if (offset / map_stride > UINT32_MAX)
        return -22;
    auto slot = find_handle(*handle.drm, offset / map_stride);
    auto start = offset % map_stride;
    if (!slot || start >= (*slot)->size || size > (*slot)->size - start)
        return -22;
    uint64_t first = (*slot)->address + start;
    for (size_t page = 0; page < size; page += page_size)
        if (page_reference_count(first + page) == UINT16_MAX)
            return -12;
    address = first;
    return 0;
}
} // namespace DrmScanout
} // namespace ax
