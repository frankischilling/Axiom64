// SPDX-License-Identifier: GPL-3.0-or-later
#include "socket_registry.hpp"
#include "core/random.hpp"

namespace ax {
static bool datagram_name_used(const UnixAddressValue& value) {
    for (const auto& socket : sockets)
        if (socket.used && socket.type == 2 && socket.datagram_name &&
            socket.datagram_name->address().same(value))
            return true;
    return false;
}

int socket_datagram_autobind(Socket& socket) {
    if (socket.datagram_name->address().length)
        return 0;
    static bool initialized;
    static uint32_t next;
    if (!initialized) {
        if (int error = random_read(&next, sizeof(next), true))
            return error;
        initialized = true;
    }
    UnixAddressValue value;
    value.length = 6;
    constexpr char hex[] = "0123456789abcdef";
    unsigned attempts = 0;
    do {
        uint32_t candidate = next++;
        for (unsigned n = 0; n < 5; n++)
            value.path[n + 1] = hex[(candidate >> ((4 - n) * 4)) & 15];
    } while (datagram_name_used(value) && ++attempts <= 256);
    if (datagram_name_used(value))
        return -98;
    return socket.datagram_name->bind(value);
}

int socket_datagram_bind(Task& task, Socket& socket, uint64_t pointer, size_t length) {
    length = uint32_t(length);
    if (length < 2 || length > 128)
        return -22;
    uint8_t input[128];
    if (!task.memory->space.copy_in(input, pointer, length))
        return -14;
    UnixAddressValue value;
    if (int error = unix_address_decode(input, length, value))
        return error;
    if (socket.datagram_name->address().length)
        return -22;
    if (!value.length)
        return socket_datagram_autobind(socket);
    if (value.abstract() && datagram_name_used(value))
        return -98;
    if (!value.abstract()) {
        Path path;
        path.base = task.fs->cwd_node;
        memcpy(path.text, value.path, value.length);
        if (lookup(path, false)) {
            return -98;
        }
        int error = create_node(path, 0140000 | (0777 & ~task.fs->umask), socket.bound_node);
        if (error) {
            return error;
        }
    }
    return socket.datagram_name->bind(value);
}

int socket_datagram_address(Task& task, uint64_t pointer, uint32_t length,
                            UnixAddressValue& address) {
    if (length < 2 || length > 128)
        return -22;
    uint8_t bytes[128];
    if (!task.memory->space.copy_in(bytes, pointer, length))
        return -14;
    UnixAddressValue result;
    if (int error = unix_address_decode(bytes, length, result))
        return error;
    if (!result.length)
        return -22;
    address = result;
    return 0;
}

namespace {
bool live(const UnixDatagramTarget& target) {
    return target.socket && target.socket->used && target.socket->generation == target.generation;
}

bool permits(const Socket& receiver, const Socket& sender) {
    return !receiver.connected ||
           (receiver.peer == &sender && receiver.peer_generation == sender.generation);
}

bool receiver_full(const Socket& receiver, const Socket& sender) {
    return &receiver != &sender &&
           !(receiver.peer == &sender && receiver.peer_generation == sender.generation) &&
           receiver.datagrams.count() > 10;
}

// Retained requests resume before the scheduler selects current. VFS lookup
// uses that global task for root, credentials and procfs links; restore it on
// every return. Kernel execution is serialized with interrupts disabled.
class LookupContext {
    Task* previous;

  public:
    explicit LookupContext(Task& task) : previous(current) {
        current = &task;
    }

    ~LookupContext() {
        current = previous;
    }
};

Socket* lookup_peer(Task& task, const UnixAddressValue& name, int& error) {
    error = -111;
    Node* node = nullptr;
    if (!name.abstract()) {
        LookupContext context(task);
        Path path;
        path.base = task.fs->cwd_node;
        memcpy(path.text, name.path, name.length);
        error = resolve_path(path, node);
        if (error)
            return nullptr;
        if ((error = node_access(node, 2)))
            return nullptr;
        node = file_node(node);
        if ((node->mode & 0170000) != 0140000) {
            error = -111;
            return nullptr;
        }
    }
    for (auto& candidate : sockets) {
        if (!candidate.used)
            continue;
        bool found = node ? candidate.bound_node && file_node(candidate.bound_node) == node
                          : candidate.type == 2 && candidate.datagram_name &&
                                candidate.datagram_name->address().same(name);
        if (!found)
            continue;
        if (candidate.type != 2) {
            error = -91;
            return nullptr;
        }
        error = 0;
        return &candidate;
    }
    error = -111;
    return nullptr;
}

void replace_peer(Socket& socket, Socket* peer) {
    UnixDatagramTarget old{socket.peer, socket.peer_generation};
    bool had_peer = socket.connected;
    auto old_name = socket.datagram_peer_name;
    socket.peer = peer;
    socket.peer_generation = peer ? peer->generation : 0;
    socket.connected = peer;
    socket.peer_closed = false;
    socket.datagram_peer_name = peer ? peer->datagram_name : nullptr;
    if (socket.datagram_peer_name)
        socket.datagram_peer_name->retain();
    if (old_name)
        old_name->drop();
    if (had_peer && (old.socket != peer || !live(old))) {
        bool lost = socket.datagrams.readable();
        socket.datagrams.clear();
        if (lost && live(old) && old.socket->peer == &socket &&
            old.socket->peer_generation == socket.generation)
            old.socket->datagram_error = 104;
    }
}
} // namespace

int socket_datagram_connect(Task& task, Socket& socket, uint64_t pointer, uint32_t length) {
    if (length < 2 || length > 128)
        return -22;
    uint8_t bytes[128];
    if (!task.memory->space.copy_in(bytes, pointer, length))
        return -14;
    uint16_t family;
    memcpy(&family, bytes, 2);
    if (!family) {
        replace_peer(socket, nullptr);
        return 0;
    }
    UnixAddressValue name;
    if (int error = unix_address_decode(bytes, length, name))
        return error;
    if (!name.length)
        return -22;
    int error;
    auto receiver = lookup_peer(task, name, error);
    if (!receiver)
        return error;
    if (!permits(*receiver, socket))
        return -1;
    replace_peer(socket, receiver);
    return 0;
}

bool socket_datagram_writable(const Socket& socket) {
    if (!socket.datagram_send->writable())
        return false;
    UnixDatagramTarget peer{socket.peer, socket.peer_generation};
    return !live(peer) || !receiver_full(*peer.socket, socket);
}

int64_t socket_datagram_write(Task& task, Socket* sender, UnixDatagramRecord* record,
                              const UnixAddressValue* named, UnixDatagramTarget& target) {
    if (sender->write_closed)
        return -32;
    for (;;) {
        bool resolved = false;
        if (!target.socket) {
            if (named) {
                int error;
                target.socket = lookup_peer(task, *named, error);
                if (!target.socket)
                    return error;
                target.generation = target.socket->generation;
            } else {
                if (sender->peer_closed) {
                    replace_peer(*sender, nullptr);
                    return -111;
                }
                if (!sender->connected || !sender->peer)
                    return -107;
                target = {sender->peer, sender->peer_generation};
            }
            resolved = true;
        }
        if (!live(target)) {
            if (sender->connected && sender->peer_generation == target.generation) {
                replace_peer(*sender, nullptr);
                return -111;
            }
            if (!named)
                return -104;
            target = {};
            continue;
        }
        auto receiver = target.socket;
        if (!permits(*receiver, *sender))
            return -1;
        if (receiver->read_closed)
            return -32;
        // Capture once for this lookup, before waiting for the receive queue.
        // A dead named receiver can trigger a fresh lookup; a mere wake cannot.
        if (resolved && (sender->pass_credentials || receiver->pass_credentials))
            record->credentials().capture(task);
        if (receiver_full(*receiver, *sender))
            return -11;
        size_t length = record->size();
        receiver->datagrams.accept(record, receiver);
        return length;
    }
}

int socket_datagram_output_name(Task& task, const UnixAddressName* name, uint64_t pointer,
                                uint64_t length_pointer) {
    uint32_t capacity;
    if (!task.memory->space.copy_in(&capacity, length_pointer, 4))
        return -14;
    if (int32_t(capacity) < 0)
        return -22;
    uint8_t bytes[111];
    uint32_t actual = name ? name->address().output(bytes, sizeof(bytes))
                           : UnixAddressValue{}.output(bytes, sizeof(bytes));
    if ((capacity && !task.memory->space.copy_out(pointer, bytes, min(capacity, actual))) ||
        !task.memory->space.copy_out(length_pointer, &actual, 4))
        return -14;
    return 0;
}
} // namespace ax
