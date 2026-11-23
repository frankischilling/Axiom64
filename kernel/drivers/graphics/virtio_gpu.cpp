// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/drivers/graphics/virtio_gpu.cpp
 * @brief   Drives a Virtio GPU 2D display.
 * @author  frankischilling
 * @date    2026-11-23
 *
 * Owns the control queue, DMA backing, and scanout update sequence.
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
#include "drivers/graphics/virtio_gpu.hpp"
#include "boot/boot.hpp"
#include "drivers/virtio/pci.hpp"
#include "mm/dma.hpp"

namespace ax {
namespace {
// Virtio 1.2 section 5.7. The x86 guest and device records are little-endian.
constexpr uint32_t get_display_info = 0x100, create_2d = 0x101, set_scanout = 0x103;
constexpr uint32_t resource_flush = 0x104, transfer_2d = 0x105, attach_backing = 0x106;
constexpr uint32_t ok_nodata = 0x1100, ok_display_info = 0x1101;
constexpr uint32_t flag_fence = 1, bgrx = 2;
constexpr unsigned num_scanouts_offset = 8, scanout_limit = 16;
constexpr uint32_t resource = 1;
constexpr size_t response_offset = page_size / 2;
constexpr uint64_t frame_limit = 64 * 1024 * 1024;
constexpr uint64_t frame_interval = 3; // The device poll runs at 100 Hz.
constexpr uint64_t command_timeout = 500;

struct Header {
    uint32_t type = 0, flags = 0;
    uint64_t fence = 0;
    uint32_t context = 0, padding = 0;
};

struct Rect {
    uint32_t x, y, width, height;
};

struct Output {
    Rect rect;
    uint32_t enabled, flags;
};

struct DisplayInfo {
    Header header;
    Output outputs[scanout_limit];
};

struct Create {
    Header header;
    uint32_t resource, format, width, height;
};

struct Scanout {
    Header header;
    Rect rect;
    uint32_t output, resource;
};

struct Attach {
    Header header;
    uint32_t resource, entries;
    uint64_t address;
    uint32_t bytes, padding;
};

struct Transfer {
    Header header;
    Rect rect;
    uint64_t offset;
    uint32_t resource, padding;
};

struct Flush {
    Header header;
    Rect rect;
    uint32_t resource, padding;
};

static_assert(sizeof(Header) == 24 && sizeof(DisplayInfo) == 408 && sizeof(Create) == 40 &&
              sizeof(Scanout) == 48 && sizeof(Attach) == 48 && sizeof(Transfer) == 56 &&
              sizeof(Flush) == 48);

enum class Update { idle, transfer, flush };

struct Gpu {
    VirtioPci pci;
    SplitQueue control, cursor;
    BootFramebuffer framebuffer{};
    Rect rect{};
    uint64_t command = 0, backing = 0, fence = 0, issued = 0, next_frame = 0;
    size_t backing_pages = 0;
    uint16_t head = 0;
    bool selected = false, live = false;
    Update update = Update::idle;
};

constinit Gpu gpu{};

uint8_t* response() {
    return static_cast<uint8_t*>(physical(gpu.command)) + response_offset;
}

template <typename Request> bool submit(Request request, size_t bytes = sizeof(Header)) {
    static_assert(sizeof(Request) <= response_offset);
    if (gpu.fence == UINT64_MAX)
        return false;
    Header& header = [&]() -> Header& {
        if constexpr (sizeof(Request) == sizeof(Header))
            return request;
        else
            return request.header;
    }();
    header.flags = flag_fence;
    header.fence = ++gpu.fence;
    memcpy(physical(gpu.command), &request, sizeof(request));
    memset(response(), 0, bytes);
    VirtioBuffer buffers[] = {{gpu.command, sizeof(request), false},
                              {gpu.command + response_offset, uint32_t(bytes), true}};
    int head = gpu.control.submit(buffers, 2, gpu.fence);
    if (head < 0)
        return false;
    gpu.head = head;
    return gpu.pci.notify(gpu.control);
}

bool checked_response(const VirtioCompletion& used, uint32_t type, size_t bytes) {
    if (used.cookie != gpu.fence || used.head != gpu.head || used.length != bytes)
        return false;
    Header header{};
    memcpy(&header, response(), sizeof(header));
    if (header.type != type || header.flags != flag_fence || header.fence != gpu.fence ||
        header.context)
        return false;
    VirtioCompletion duplicate{};
    return gpu.control.complete(duplicate) == 0;
}

template <typename Request>
bool exchange(Request request, uint32_t type = ok_nodata, size_t bytes = sizeof(Header)) {
    VirtioCompletion used{};
    return submit(request, bytes) && gpu.pci.wait(gpu.control, used, 1) == 0 &&
           checked_response(used, type, bytes);
}

Transfer transfer_request() {
    return {{transfer_2d}, gpu.rect, 0, resource, 0};
}

Flush flush_request() {
    return {{resource_flush}, gpu.rect, resource, 0};
}

void initialization_failed(const char* reason) {
    const bool reset = gpu.pci.stop();
    if (reset) {
        gpu.control.release();
        gpu.cursor.release();
        if (gpu.command)
            page_free(gpu.command);
        if (gpu.backing)
            page_free(gpu.backing, gpu.backing_pages);
    }
    log("virtio-gpu: setup failed at %s reset=%u\n", reason, uint64_t(reset));
}

bool select_output(uint32_t& output) {
    uint32_t count = 0;
    if (!gpu.pci.read_config(num_scanouts_offset, &count, sizeof(count)) || !count ||
        count > scanout_limit ||
        !exchange(Header{get_display_info}, ok_display_info, sizeof(DisplayInfo)))
        return false;
    DisplayInfo info{};
    memcpy(&info, response(), sizeof(info));
    for (output = 0; output < count; ++output) {
        const auto& mode = info.outputs[output];
        const auto& rect = mode.rect;
        if (mode.enabled && rect.width && rect.height && uint64_t(rect.width) * 4 <= frame_limit &&
            rect.height <= frame_limit / (uint64_t(rect.width) * 4)) {
            gpu.rect = {0, 0, rect.width, rect.height};
            return true;
        }
    }
    return false;
}

void attach(const PciFunction& function) {
    if (gpu.selected || function.read32(0) != 0x10501af4)
        return;
    gpu.selected = true;
    if (!gpu.pci.open(function, 0, 16) || !gpu.pci.modern() ||
        !gpu.pci.setup_queue(gpu.control, 0, 8, 2) || !gpu.pci.setup_queue(gpu.cursor, 1, 2, 1) ||
        !(gpu.command = Dma::allocate(1, Dma::pci)) || !gpu.pci.start()) {
        initialization_failed("transport");
        return;
    }
    uint32_t output;
    if (!select_output(output)) {
        initialization_failed("display-info");
        return;
    }
    const uint64_t pitch = uint64_t(gpu.rect.width) * 4;
    const uint32_t bytes = pitch * gpu.rect.height;
    gpu.backing_pages = align_up(bytes) / page_size;
    gpu.backing = Dma::allocate(gpu.backing_pages, Dma::pci);
    if (!gpu.backing ||
        !exchange(Create{{create_2d}, resource, bgrx, gpu.rect.width, gpu.rect.height}) ||
        !exchange(Attach{{attach_backing}, resource, 1, gpu.backing, bytes, 0}) ||
        !exchange(Scanout{{set_scanout}, gpu.rect, output, resource}) ||
        !exchange(transfer_request()) || !exchange(flush_request())) {
        initialization_failed("scanout");
        return;
    }

    gpu.framebuffer = {
        physical(gpu.backing), gpu.rect.width, gpu.rect.height, pitch, 32, 8, 16, 8, 8, 8, 0};
    gpu.live = true;
    log("virtio-gpu: scanout=%u %ux%u pitch=%u\n", uint64_t(output), uint64_t(gpu.rect.width),
        uint64_t(gpu.rect.height), pitch);
}

void stop_updates(const char* reason) {
    // An open mapping can still point at the backing. The DMA storage stays
    // reserved for the boot lifetime if completions can no longer be trusted.
    gpu.live = false;
    log("virtio-gpu: display updates stopped at %s\n", reason);
}
} // namespace

const BootFramebuffer* virtio_gpu_scanout_init() {
    pci_scan(attach);
    return gpu.live ? &gpu.framebuffer : nullptr;
}

bool virtio_gpu_request_refresh() {
    if (!gpu.live)
        return false;
    gpu.next_frame = 0;
    return true;
}

void virtio_gpu_poll(uint64_t now) {
    if (!gpu.live)
        return;
    if (!gpu.pci.healthy()) {
        stop_updates("device-status");
        return;
    }
    if (gpu.update != Update::idle) {
        VirtioCompletion used{};
        const int result = gpu.control.complete(used);
        if (result < 0) {
            stop_updates("queue");
            return;
        }
        if (!result) {
            if (now - gpu.issued >= command_timeout)
                stop_updates("timeout");
            return;
        }
        // A delayed poll can observe a response after its wait deadline.
        if (!checked_response(used, ok_nodata, sizeof(Header))) {
            stop_updates("response");
            return;
        }
        if (gpu.update == Update::transfer) {
            if (!submit(flush_request()))
                stop_updates("flush");
            else {
                gpu.issued = now;
                gpu.update = Update::flush;
            }
            return;
        }
        gpu.update = Update::idle;
    }
    if (now >= gpu.next_frame) {
        if (!submit(transfer_request())) {
            stop_updates("transfer");
            return;
        }
        gpu.issued = now;
        gpu.next_frame = now + frame_interval;
        gpu.update = Update::transfer;
    }
}
} // namespace ax
