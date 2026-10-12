// SPDX-License-Identifier: GPL-3.0-or-later
#include "drivers/random/virtio.hpp"
#include "drivers/random/sample.hpp"
#include "drivers/virtio/pci.hpp"
#include "core/random.hpp"
#include "core/random/engine.hpp"

namespace ax {
namespace {
struct Controller {
    VirtioPci pci;
    SplitQueue queue;
    EntropyRequest request;
    random::SeedSource source{true, EntropyRequest::word, &request};
    uint64_t buffer = 0, cookie = 0, next_sample = 0;
    bool live = false, trusted = false;
};

constinit static Controller controllers[4]{};
static unsigned attempts;
static bool trust_policy;

static uint64_t after(uint64_t now, uint64_t interval) {
    return now > UINT64_MAX - interval ? UINT64_MAX : now + interval;
}

static void failed(Controller& device, const char* reason) {
    device.live = false;
    device.request.reset();
    bool reset = device.pci.stop();
    if (reset) {
        device.queue.release();
        if (device.buffer) {
            random::erase(physical(device.buffer), page_size);
            page_free(device.buffer);
            device.buffer = 0;
        }
    }
    // A device which did not acknowledge reset may still DMA; retain its storage.
    log("RANDOM_VIRTIO_FAILED reason=%s quarantined=%u\n", reason, uint64_t(!reset));
}

static bool submit(Controller& device, uint64_t now) {
    if (device.cookie == UINT64_MAX)
        return false;
    random::erase(physical(device.buffer), 32);
    VirtioBuffer writable{device.buffer, device.request.remaining(), true};
    uint64_t cookie = ++device.cookie;
    int head = device.queue.submit(&writable, 1, cookie);
    return head >= 0 && device.request.begin(cookie, head, now) && device.pci.notify(device.queue);
}

static void poll(Controller& device, uint64_t now) {
    if (!device.live)
        return;
    if (!device.pci.healthy()) {
        failed(device, "device-status");
        return;
    }
    if (device.request.pending()) {
        VirtioCompletion used{};
        int status = device.queue.complete(used);
        if (!status) {
            if (device.request.expired(now))
                failed(device, "timeout");
            return;
        }
        if (status < 0 || device.request.expired(now)) {
            failed(device, status < 0 ? "queue-ownership" : "timeout");
            return;
        }
        int result =
            device.request.complete(used.cookie, used.head, physical(device.buffer), used.length);
        if (result < 0) {
            failed(device, "completion-length-or-owner");
            return;
        }
        random::erase(physical(device.buffer), 32);
        log("RANDOM_VIRTIO_COMPLETE cookie=%u length=%u accumulated=%u transport=%s\n", used.cookie,
            uint64_t(used.length), uint64_t(device.request.accumulated()),
            device.pci.modern() ? "modern" : "legacy");
        // There is exactly one outstanding descriptor. Reject already-published duplicates
        // before giving the device another request with a recycled descriptor head.
        VirtioCompletion extra{};
        if (device.queue.complete(extra) != 0) {
            failed(device, "extra-completion");
            return;
        }
        if (result == 1) {
            bool accepted = random_sample_source(device.source, "virtio", device.trusted);
            if (!accepted)
                log("RANDOM_VIRTIO_REJECTED reason=sample-health bits=0\n");
            device.request.reset();
            device.next_sample = after(now, accepted ? 6000 : 10);
        }
    }
    if (!device.request.pending() && now >= device.next_sample && !submit(device, now))
        failed(device, "request-submit");
}

static void attach(const PciFunction& function) {
    uint16_t id = function.read16(2);
    if (attempts == 4 || function.read16(0) != 0x1af4 || (id != 0x1005 && id != 0x1044))
        return;
    auto& device = controllers[attempts++];
    device.trusted = trust_policy;
    if (!device.pci.open(function, 0, 0) || !device.pci.setup_queue(device.queue, 0, 8, 1) ||
        !(device.buffer = page_alloc()) || !device.pci.start()) {
        failed(device, "initialization");
        return;
    }
    device.live = true;
    log("RANDOM_VIRTIO_SOURCE transport=%s trusted=%u queue=%u\n",
        device.pci.modern() ? "modern" : "legacy", uint64_t(device.trusted),
        uint64_t(device.queue.layout().size));
}
} // namespace

void virtio_rng_init(bool trusted) {
    trust_policy = trusted;
    pci_scan(attach);
}

void virtio_rng_poll(uint64_t now) {
    for (unsigned i = 0; i < attempts; i++)
        poll(controllers[i], now);
}
} // namespace ax
