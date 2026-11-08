// SPDX-License-Identifier: GPL-3.0-or-later
#include "ipc/ipc.hpp"
#include "ipc/unix_rights.hpp"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

namespace {
ax::Handle descriptions[ax::max_handles];
unsigned closed[ax::max_handles];
size_t allocations;
bool refuse;
unsigned closing;
} // namespace

namespace ax {
extern Socket sockets[256];

[[noreturn]] void panic(const char*) {
    abort();
}

void* alloc(size_t size) {
    if (refuse)
        return nullptr;
    void* pointer = malloc(size);
    if (pointer)
        allocations++;
    return pointer;
}

void release(void* pointer) {
    if (!pointer)
        return;
    assert(allocations);
    allocations--;
    free(pointer);
}

void retain(Handle* handle) {
    assert(handle && handle->references);
    handle->references++;
}

// Filesystem adapter: description references are real, and final socket close
// crosses the production close/queue implementation. No userspace table is faked.
void close_handle(Handle* handle) {
    assert(handle && handle->references);
    closing++;
    if (!--handle->references) {
        closed[handle - descriptions]++;
        if (handle->socket)
            socket_close(handle->socket);
        handle->socket = nullptr;
    }
    if (!--closing)
        unix_collect_rights();
}
} // namespace ax

static ax::Handle* description() {
    for (auto& handle : descriptions)
        if (!handle.references) {
            handle = {};
            handle.references = 1;
            return &handle;
        }
    abort();
}

static ax::Handle* endpoint() {
    for (auto& socket : ax::sockets)
        if (!socket.used) {
            socket = {};
            socket.used = true;
            socket.type = 2;
            socket.datagram_send = ax::UnixSendBudget::create();
            socket.datagram_name = ax::UnixAddressName::create({});
            assert(socket.datagram_send && socket.datagram_name);
            auto handle = description();
            handle->socket = &socket;
            socket.description = handle;
            return handle;
        }
    abort();
}

static ax::UnixRights* rights(uint32_t uid, ax::Handle* first, ax::Handle* second = nullptr) {
    auto list = ax::UnixRights::create(uid);
    assert(list);
    list->append(first);
    if (second)
        list->append(second);
    return list;
}

static void enqueue(ax::Handle* receiver, ax::UnixRights* list) {
    int error;
    auto record = ax::UnixDatagramRecord::create(*receiver->socket->datagram_send, 1, error);
    assert(record && !error);
    record->data()[0] = 'Q';
    record->take_rights(list);
    assert(!list);
    receiver->socket->datagrams.accept(record, receiver->socket);
}

static void empty() {
    assert(!allocations && !closing);
    for (const auto& handle : descriptions)
        assert(!handle.references);
    for (const auto& socket : ax::sockets)
        assert(!socket.used);
}

static void retained() {
    auto receiver = endpoint();
    auto file = description();
    unsigned old = closed[file - descriptions];
    enqueue(receiver, rights(5, file, file));
    assert(file->references == 3);
    ax::close_handle(file);
    assert(file->references == 2 && closed[file - descriptions] == old);
    receiver->socket->datagrams.consume();
    assert(!file->references && closed[file - descriptions] == old + 1);
    ax::close_handle(receiver);
    empty();
}

static void self_cycle() {
    for (unsigned repeat = 0; repeat < 300; repeat++) {
        auto receiver = endpoint();
        enqueue(receiver, rights(7, receiver));
        ax::unix_collect_rights();
        assert(receiver->references == 2 && receiver->socket->datagrams.count() == 1);
        ax::close_handle(receiver);
        empty();
    }
}

static void rooted_ring(unsigned count) {
    ax::Handle* ring[64];
    assert(count >= 2 && count <= 64);
    for (unsigned index = 0; index < count; index++)
        ring[index] = endpoint();
    auto file = description();
    for (unsigned index = 0; index < count; index++)
        enqueue(ring[index], rights(9, ring[(index + 1) % count], file));
    ax::close_handle(file);
    for (unsigned index = 1; index < count; index++)
        ax::close_handle(ring[index]);
    ax::unix_collect_rights();
    for (unsigned index = 0; index < count; index++)
        assert(ring[index]->references && ring[index]->socket->datagrams.count() == 1);
    ax::close_handle(ring[0]);
    empty();
}

static void pending_root() {
    auto receiver = endpoint();
    enqueue(receiver, rights(10, receiver));
    auto pending = rights(10, receiver);
    ax::close_handle(receiver);
    assert(receiver->references == 2 && receiver->socket->datagrams.count() == 1);
    pending->drop();
    empty();
}

static void user_pressure() {
    auto receiver = endpoint();
    auto file = description();
    auto pending = rights(44, file);
    assert(!pending->admission(1, false));
    enqueue(receiver, rights(44, file));
    assert(!pending->admission(1, false));
    enqueue(receiver, rights(44, file));
    assert(pending->admission(1, false) == -109 && !pending->admission(1, true));
    auto other = rights(45, file);
    assert(!other->admission(0, false));
    receiver->socket->datagrams.consume();
    assert(!pending->admission(1, false));
    other->drop();
    pending->drop();
    ax::close_handle(file);
    ax::close_handle(receiver);
    empty();
}

static void refusal_and_maximum() {
    auto file = description();
    refuse = true;
    assert(!ax::UnixRights::create(0) && file->references == 1);
    refuse = false;
    auto list = ax::UnixRights::create(0);
    assert(list);
    for (unsigned index = 0; index < ax::UnixRights::maximum; index++)
        list->append(file);
    assert(list->size() == 253 && file->references == 254);
    list->drop();
    assert(file->references == 1);
    ax::close_handle(file);
    empty();
}

int main() {
    retained();
    self_cycle();
    rooted_ring(2);
    rooted_ring(64);
    pending_root();
    user_pressure();
    refusal_and_maximum();
    puts("UNIX_RIGHTS_POLICY_PASS retained_descriptions self_cycles rooted_rings pending_roots "
         "user_pressure allocation_refusal maximum_capture");
}
