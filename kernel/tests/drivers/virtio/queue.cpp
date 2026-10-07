// SPDX-License-Identifier: GPL-3.0-or-later
#include <cstdio>
#include <cstdlib>
#include "drivers/virtio/queue.hpp"

#define CHECK(value) do { if (!(value)) { std::printf("VIRTQUEUE_FAIL line=%d: %s\n", __LINE__, #value); std::exit(1); } } while (0)
namespace {
size_t pages_live, allocations_live;
bool fail_pages, fail_metadata;
}
namespace ax {
uint64_t direct_map = 0;
uint64_t page_alloc(size_t count) {
    if (fail_pages) return 0;
    void* memory = std::aligned_alloc(page_size, count * page_size);
    if (memory) pages_live += count;
    return reinterpret_cast<uint64_t>(memory);
}
void page_free(uint64_t address, size_t count) {
    CHECK(pages_live >= count);
    pages_live -= count;
    std::free(reinterpret_cast<void*>(address));
}
void* alloc(size_t bytes) {
    if (fail_metadata) return nullptr;
    void* memory = std::calloc(1, bytes);
    if (memory) allocations_live++;
    return memory;
}
void release(void* memory) {
    CHECK(memory && allocations_live);
    allocations_live--;
    std::free(memory);
}
}
namespace {
using namespace ax;
struct WireDescriptor { uint64_t address; uint32_t length; uint16_t flags, next; };
static_assert(sizeof(WireDescriptor) == 16);
// Simulated device observes only the wire layout, not the queue's CPU metadata.
struct Device {
    VirtioQueueLayout layout;
    volatile uint16_t* available;
    volatile uint16_t* used;
    uint16_t taken = 0, produced = 0;
    explicit Device(const SplitQueue& queue) : layout(queue.layout()),
        available((volatile uint16_t*)physical(layout.available)),
        used((volatile uint16_t*)physical(layout.used)) {
        CHECK(layout.size && available[0] == 1 && available[1] == 0 && used[1] == 0);
    }
    uint16_t take() {
        CHECK(uint16_t(available[1] - taken));
        virtio_dma_barrier();
        return available[2 + (taken++ & (layout.size - 1))];
    }
    WireDescriptor descriptor(unsigned index) const {
        CHECK(index < layout.size);
        WireDescriptor result{};
        memcpy(&result, physical(layout.descriptors + index * sizeof(result)), sizeof(result));
        return result;
    }
    void check_chain(uint16_t head, const VirtioBuffer* buffers, unsigned count) const {
        unsigned at = head;
        for (unsigned i = 0; i < count; i++) {
            const auto d = descriptor(at);
            CHECK(d.address == buffers[i].address && d.length == buffers[i].length);
            CHECK(d.flags == ((buffers[i].writable ? 2 : 0) | (i + 1 < count ? 1 : 0)));
            at = d.next;
        }
    }
    void finish(uint32_t head, uint32_t length) {
        uint32_t entry[2]{head, length};
        memcpy(physical(layout.used + 4 + size_t(produced & (layout.size - 1)) * sizeof(entry)), entry, sizeof(entry));
        virtio_dma_barrier();
        used[1] = ++produced;
        virtio_dma_barrier();
    }
};
static void consume(SplitQueue& queue, uint16_t head, uint64_t cookie, uint32_t length) {
    VirtioCompletion result{};
    CHECK(queue.complete(result) == 1);
    CHECK(result.head == head && result.cookie == cookie && result.length == length);
}
static void clean(SplitQueue& queue) {
    CHECK(queue.release());
    CHECK(!queue.layout().size && !queue.layout().descriptors && !queue.layout().used);
    CHECK(!pages_live && !allocations_live);
}
static void geometry_and_rollover() {
    const uint16_t sizes[]{1, 2, 4, 8, 256, 32768};
    const VirtioBuffer buffer{0x1000, 64, true};
    for (uint16_t size : sizes) {
        SplitQueue queue;
        CHECK(queue.create(size));
        CHECK(!queue.create(size));
        Device device(queue);
        auto heads = (uint16_t*)std::malloc(size_t(size) * sizeof(uint16_t));
        CHECK(heads);
        for (unsigned i = 0; i < size; i++) {
            int head = queue.submit(&buffer, 1, 100000 + i);
            CHECK(head >= 0);
            heads[i] = head;
        }
        CHECK(queue.submit(&buffer, 1, 0) == -11);
        for (unsigned i = 0; i < size; i++) {
            CHECK(device.take() == heads[i]);
            device.check_chain(heads[i], &buffer, 1);
            device.finish(heads[i], 64);
            consume(queue, heads[i], 100000 + i, 64);
        }
        VirtioCompletion result{};
        CHECK(queue.complete(result) == 0);
        std::free(heads);
        clean(queue);
    }
    SplitQueue queue;
    CHECK(queue.create(4));
    Device device(queue);
    for (unsigned i = 0; i < 70000; i++) {
        int head = queue.submit(&buffer, 1, i);
        CHECK(head >= 0 && device.take() == head);
        device.finish(head, 64);
        consume(queue, head, i, 64);
    }
    CHECK(device.available[1] == uint16_t(70000) && device.used[1] == uint16_t(70000));
    clean(queue);
    std::puts("VIRTQUEUE_GEOMETRY_WRAP_PASS requests=70000");
}
static void concurrent_chains() {
    SplitQueue queue;
    CHECK(queue.create(8));
    Device device(queue);
    const VirtioBuffer buffers[]{{0x2000, 16, false}, {0x3000, 32, true}, {0x4000, 1, true}};
    int a = queue.submit(buffers, 3, 101), b = queue.submit(buffers, 3, 102);
    int c = queue.submit(buffers, 2, 103);
    CHECK(a >= 0 && b >= 0 && c >= 0 && a != b && b != c && a != c);
    CHECK(queue.submit(buffers, 1, 104) == -11);
    CHECK(device.take() == a && device.take() == b && device.take() == c);
    device.check_chain(a, buffers, 3);
    device.check_chain(b, buffers, 3);
    device.check_chain(c, buffers, 2);
    device.finish(b, 33); // Device may complete heads out of submission order.
    consume(queue, b, 102, 33);
    int d = queue.submit(buffers, 3, 104);
    CHECK(d >= 0 && d != a && d != c && device.take() == d);
    device.check_chain(a, buffers, 3); // Other device-owned descriptors survive.
    device.check_chain(c, buffers, 2);
    device.check_chain(d, buffers, 3);
    // CPU reclamation must not follow an untrusted next field in DMA memory.
    WireDescriptor damaged = device.descriptor(a);
    damaged.next = 0xffff;
    memcpy(physical(device.layout.descriptors + a * sizeof(damaged)), &damaged, sizeof(damaged));
    device.finish(c, 32);
    device.finish(a, 33);
    device.finish(d, UINT32_MAX); // Used-length policy belongs to the driver.
    consume(queue, c, 103, 32);
    consume(queue, a, 101, 33);
    consume(queue, d, 104, UINT32_MAX);
    int again = queue.submit(buffers, 3, 105);
    CHECK(again >= 0 && device.take() == again);
    device.check_chain(again, buffers, 3);
    device.finish(again, 33);
    consume(queue, again, 105, 33);
    clean(queue);
    std::puts("VIRTQUEUE_CONCURRENT_CHAINS_PASS");
}
static void bad_completions() {
    const VirtioBuffer buffers[]{{0x2000, 16, false}, {0x3000, 32, true}};
    for (unsigned variant = 0; variant < 5; variant++) {
        SplitQueue queue;
        CHECK(queue.create(4));
        Device device(queue);
        int head = queue.submit(buffers, 2, 42);
        CHECK(head >= 0 && device.take() == head);
        if (variant == 0) device.finish(UINT32_MAX, 1);
        if (variant == 1) device.finish(device.descriptor(head).next, 1);
        if (variant == 2) { device.finish(head, 1); device.finish(head, 1); }
        if (variant == 3) device.finish(device.layout.size, 1);
        if (variant == 4) {
            device.finish(head, 1);
            consume(queue, head, 42, 1);
            int other = queue.submit(buffers, 1, 43);
            CHECK(other >= 0 && other != head && device.take() == other);
            device.finish(head, 1); // Previously completed head, now free/member.
        }
        VirtioCompletion result{};
        CHECK(queue.complete(result) == -5);
        CHECK(queue.complete(result) == -5 && queue.submit(buffers, 1, 44) == -5);
        clean(queue);
    }
    std::puts("VIRTQUEUE_INVALID_COMPLETION_PASS");
}
static void errors_and_allocation() {
    SplitQueue queue;
    CHECK(!queue.create(0) && !queue.create(3) && !queue.create(65535));
    fail_pages = true;
    CHECK(!queue.create(8));
    fail_pages = false;
    CHECK(!pages_live && !allocations_live);
    fail_metadata = true;
    CHECK(!queue.create(8));
    fail_metadata = false;
    CHECK(!pages_live && !allocations_live);
    CHECK(queue.create(4));
    Device device(queue);
    const VirtioBuffer buffers[]{{0x2000, 16, false}, {0x3000, 32, true}};
    CHECK(queue.submit(nullptr, 1, 0) == -22 && queue.submit(buffers, 0, 0) == -22);
    CHECK(queue.submit(buffers, 5, 0) == -22);
    const VirtioBuffer order[]{{0x2000, 16, true}, {0x3000, 32, false}};
    CHECK(queue.submit(order, 2, 0) == -22);
    const VirtioBuffer address[]{ {1ull << 52, 1, true}, {(1ull << 52) - 1, 2, true} };
    CHECK(queue.submit(address, 1, 0) == -22 && queue.submit(address + 1, 1, 0) == -22);
    const VirtioBuffer oversized[]{{0x2000, UINT32_MAX, false}, {0x3000, 1, true}};
    CHECK(queue.submit(oversized, 2, 0) == -22 && device.available[1] == 0);
    int head = queue.submit(buffers, 2, 99);
    CHECK(head >= 0 && device.take() == head);
    device.finish(head, 32);
    consume(queue, head, 99, 32);
    clean(queue);
    CHECK(queue.release());
    std::puts("VIRTQUEUE_ERROR_ALLOCATION_PASS");
}
}
int main() {
    geometry_and_rollover();
    concurrent_chains();
    bad_completions();
    errors_and_allocation();
    std::puts("VIRTQUEUE_TESTS_PASS");
}
