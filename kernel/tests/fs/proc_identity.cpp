// SPDX-License-Identifier: GPL-3.0-or-later
#include "fs/proc.hpp"
#include "fs/proc/ipv6.hpp"
#include "process/task.hpp"
#include "core/random.hpp"
#include "core/random/primitives.hpp"
#include <cassert>
#include <cstdio>
#include <cstdlib>

namespace ax {
Task tasks[max_tasks]{};
Task* current = nullptr;
uint64_t ticks = 0;
static bool ready = false;
static int random_error = 0;
static unsigned random_calls = 0;
static Node* retained = nullptr;

void* alloc(size_t size) {
    return std::malloc(size);
}

void release(void* memory) {
    std::free(memory);
}

Timestamp node_now() {
    return {};
}

Node* directory_parent(Node* node) {
    return node->parent ? node->parent : node;
}

bool node_referenced(Node* node) {
    for (auto item = retained; item; item = item->parent)
        if (item == node)
            return true;
    return false;
}

int random_read(void* output, size_t size, bool insecure) {
    assert(!insecure && size == 16);
    random_calls++;
    if (random_error)
        return random_error;
    if (!ready)
        return -11;
    auto bytes = static_cast<uint8_t*>(output);
    for (size_t i = 0; i < size; i++)
        bytes[i] = uint8_t(i);
    return 0;
}

namespace random {
void erase(void* memory, size_t length) {
    auto bytes = static_cast<volatile uint8_t*>(memory);
    while (length--)
        *bytes++ = 0;
}
} // namespace random

// This model isolates process identity and boot UUIDs. Network configuration
// uses its real backend in the IPv6 model and in guest ABI tests.
namespace proc6 {
const char* property_name(unsigned) {
    std::abort();
}

const char* scope_name(unsigned) {
    return nullptr;
}

bool scope_index(const char*, unsigned&) {
    return false;
}

int64_t read(unsigned, unsigned, uint64_t&, void*, size_t) {
    std::abort();
}

int64_t write(unsigned, unsigned, uint64_t&, const void*, size_t) {
    std::abort();
}
} // namespace proc6
} // namespace ax

static ax::Node* child(ax::Node* parent, const char* name) {
    ax::Node* result = nullptr;
    assert(ax::procfs_ops.lookup(parent, name, result) == 0 && result);
    return result;
}

static unsigned long long start(const char* text) {
    const char* cursor = nullptr;
    for (auto item = text; *item; item++)
        if (*item == ')')
            cursor = item;
    assert(cursor && cursor[1] == ' ' && cursor[3] == ' ');
    cursor += 4;
    unsigned long long result = 0;
    for (unsigned field = 4; field <= 52; field++) {
        char* end = nullptr;
        auto value = std::strtoll(cursor, &end, 10);
        assert(end != cursor && (*end == ' ' || (field == 52 && *end == '\n')));
        if (field == 22)
            result = static_cast<unsigned long long>(value);
        cursor = end + 1;
    }
    assert(!*cursor);
    return result;
}

int main() {
    ax::Mount mount{}, second{};
    mount.root = ax::procfs_root(&mount);
    second.root = ax::procfs_root(&second);
    assert(mount.root && second.root);
    auto identifier = child(child(child(child(mount.root, "sys"), "kernel"), "random"), "boot_id");
    assert(identifier->mode == (ax::regular_file | 0444) && !identifier->uid && !identifier->gid);
    char bytes[2048]{};
    bytes[0] = 'x';
    assert(ax::procfs_ops.read(identifier, 0, bytes, sizeof(bytes)) == -11 && bytes[0] == 'x');
    ax::random_error = -5;
    assert(ax::procfs_ops.read(identifier, 0, bytes, sizeof(bytes)) == -5 && bytes[0] == 'x');
    ax::random_error = 0;
    ax::ready = true;
    assert(ax::procfs_ops.read(identifier, 0, bytes, sizeof(bytes)) == 37);
    assert(!strcmp(bytes, "00010203-0405-4607-8809-0a0b0c0d0e0f\n"));
    assert(ax::random_calls == 3);
    ax::ready = false;
    ax::random_error = -5;
    auto again = child(child(child(child(second.root, "sys"), "kernel"), "random"), "boot_id");
    assert(ax::procfs_ops.read(again, 0, bytes, 8) == 8 && ax::random_calls == 3);
    assert(ax::procfs_ops.read(again, 8, bytes + 8, 29) == 29 && ax::random_calls == 3);
    assert(ax::procfs_ops.read(again, 37, bytes, 1) == 0);
    assert(ax::procfs_ops.write(identifier, 0, "x", 1) < 0);

    ax::Process process{};
    ax::MemoryContext memory{};
    ax::FsContext fs{};
    auto& task = ax::tasks[0];
    task.state = ax::State::runnable;
    task.pid = process.pid = 41;
    task.process = &process;
    task.memory = &memory;
    task.fs = &fs;
    task.credentials.user.effective = 1000;
    task.credentials.group.effective = 1001;
    process.start_ticks = task.start_ticks = 12345;
    process.parent = 2;
    process.pgid = 41;
    process.sid = 2;
    memcpy(process.executable, "/bin/name ) space", 18);
    ax::current = &task;
    auto directory = child(mount.root, "41");
    auto metadata = child(directory, "stat");
    assert(metadata->mode == (ax::regular_file | 0444));
    assert(metadata->uid == 1000 && metadata->gid == 1001);
    memory.dumpable = false;
    ax::procfs_ops.refresh(metadata);
    assert(!metadata->uid && !metadata->gid);
    memory.dumpable = true;
    ax::procfs_ops.refresh(metadata);
    assert(metadata->uid == 1000 && metadata->gid == 1001);
    ax::Handle buffered{}, unread{};
    buffered.node = unread.node = metadata;
    assert(ax::procfs_ops.read_description(&buffered, 0, bytes, 7) == 7);
    auto count = ax::procfs_ops.read_description(&buffered, 7, bytes + 7, sizeof(bytes) - 8);
    assert(count > 0);
    bytes[count + 7] = 0;
    assert(start(bytes) == 12345);
    ax::retained = metadata;
    task.state = ax::State::empty;
    assert(ax::procfs_ops.read_description(&buffered, 7, bytes + 7, sizeof(bytes) - 8) == count);
    assert(ax::procfs_ops.read_description(&unread, 0, bytes, sizeof(bytes)) == -3);
    assert(ax::procfs_ops.read_description(&buffered, 0, bytes, sizeof(bytes)) == -3);
    ax::procfs_ops.close_description(&buffered);
    ax::procfs_ops.close_description(&unread);
    ax::Node* missing = nullptr;
    assert(ax::procfs_ops.lookup(directory, "stat", missing) == -2);
    ax::retained = nullptr;
    task.state = ax::State::runnable;
    task.pid = process.pid = 42;
    process.start_ticks = task.start_ticks = 12346;
    metadata = child(child(mount.root, "42"), "stat");
    count = ax::procfs_ops.read(metadata, 0, bytes, sizeof(bytes) - 1);
    assert(count > 0);
    bytes[count] = 0;
    assert(start(bytes) == 12346);
    ax::procfs_ops.destroy(&mount);
    ax::procfs_ops.destroy(&second);
    std::puts("PROC_IDENTITY_KERNEL_PASS secure_uuid=1 lifetime=1 slot_recycle=1");
}
