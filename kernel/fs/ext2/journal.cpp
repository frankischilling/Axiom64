// SPDX-License-Identifier: GPL-3.0-or-later
#include "fs/ext2/journal.hpp"
#include "core/base.hpp"

namespace ax {
namespace {
constexpr uint32_t magic = 0xc03b3998, descriptor = 1, commit = 2, super_v2 = 4, revoke = 5;
constexpr unsigned escape = 1, same_uuid = 2, last_tag = 8, max_replay = 4096;
constexpr unsigned max_block = 4096;

uint32_t get(const uint8_t* p) {
    return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) | (uint32_t(p[2]) << 8) | p[3];
}

void put(uint8_t* p, uint32_t value) {
    p[0] = value >> 24;
    p[1] = value >> 16;
    p[2] = value >> 8;
    p[3] = value;
}

struct Replay {
    uint32_t target, position;
    bool escaped;
};
} // namespace

struct Journal {
    JournalStorage io;
    uint8_t header[max_block], *reserved;
    Replay* plan;
    uint32_t first, length, sequence, start, next_sequence;
    unsigned plan_count;
    bool scanned, staged, retrying;
    uint64_t retry_hash;
    size_t retry_count;

    bool target(uint32_t block) const {
        return block < io.volume_blocks && !(reserved[block / 8] & (1u << (block % 8)));
    }

    uint32_t next(uint32_t position) const {
        return position + 1 == length ? first : position + 1;
    }

    int read(uint32_t position, uint8_t* data) const {
        return io.read(io.context, io.blocks[position], data);
    }

    int write(uint32_t position, const uint8_t* data) const {
        return io.write(io.context, io.blocks[position], data);
    }

    int super(uint32_t id, uint32_t position) {
        put(header + 24, id);
        put(header + 28, position);
        int error = write(0, header);
        return error ? error : io.flush(io.context);
    }

    int payload(const Replay& row, uint8_t* data) const {
        int error = read(row.position, data);
        if (!error && row.escaped) {
            if (get(data) != 0)
                return -117;
            put(data, magic);
        }
        return error;
    }

    int scan();
};

void journal_close(Journal* journal) {
    if (!journal)
        return;
    release(journal->plan);
    release(journal->reserved);
    release(journal);
}

bool journal_pending(const Journal* journal) {
    return journal && (journal->start || journal->retrying);
}

Journal* journal_open(const JournalStorage& io, const uint8_t uuid[16], int& error) {
    error = -117;
    if (!uuid || !io.blocks || !io.read || !io.write || !io.flush ||
        (io.block_size != 1024 && io.block_size != 2048 && io.block_size != 4096) ||
        io.count < 1024 || io.count > io.volume_blocks)
        return nullptr;
    auto journal = static_cast<Journal*>(alloc(sizeof(Journal)));
    if (!journal) {
        error = -12;
        return nullptr;
    }
    memset(journal, 0, sizeof(Journal));
    journal->io = io;
    size_t bytes = (uint64_t(io.volume_blocks) + 7) / 8;
    journal->reserved = static_cast<uint8_t*>(alloc(bytes));
    journal->plan = static_cast<Replay*>(alloc(sizeof(Replay) * max_replay));
    if (!journal->reserved || !journal->plan) {
        error = -12;
        journal_close(journal);
        return nullptr;
    }
    memset(journal->reserved, 0, bytes);
    for (uint32_t index = 0; index < io.count; index++) {
        uint32_t block = io.blocks[index];
        if (block >= io.volume_blocks || (journal->reserved[block / 8] & (1u << (block % 8)))) {
            journal_close(journal);
            return nullptr;
        }
        journal->reserved[block / 8] |= 1u << (block % 8);
    }
    error = journal->read(0, journal->header);
    if (error) {
        journal_close(journal);
        return nullptr;
    }
    const auto header = journal->header;
    error = -117;
    if (get(header) != magic) {
        journal_close(journal);
        return nullptr;
    }
    if (get(header + 4) != super_v2 || get(header + 36) || (get(header + 40) & ~1u) ||
        get(header + 44) || header[80] || get(header + 84)) {
        error = -95;
        journal_close(journal);
        return nullptr;
    }
    journal->first = get(header + 20);
    journal->length = get(header + 16);
    journal->sequence = get(header + 24);
    journal->start = get(header + 28);
    if (get(header + 12) != io.block_size || journal->length != io.count || !journal->first ||
        journal->first >= journal->length ||
        (journal->start &&
         (journal->start < journal->first || journal->start >= journal->length)) ||
        get(header + 32) || memcmp(header + 48, uuid, 16) || get(header + 64) != 1 ||
        get(header + 68)) {
        journal_close(journal);
        return nullptr;
    }
    // Empty logs can still contain records from an abandoned transaction.
    // Start with a new ID before publishing a log head over those records.
    if (!journal->start)
        journal->sequence++;
    journal->next_sequence = journal->sequence;
    error = 0;
    return journal;
}

int Journal::scan() {
    if (scanned)
        return 0;
    if (!start) {
        scanned = true;
        return 0;
    }
    auto pending = static_cast<Replay*>(alloc(sizeof(Replay) * max_replay));
    auto revoked = static_cast<uint32_t*>(alloc(sizeof(uint32_t) * max_replay));
    if (!pending || !revoked) {
        release(pending);
        release(revoked);
        return -12;
    }
    uint32_t position = start, id = sequence, consumed = 0;
    unsigned pending_count = 0, revoked_count = 0;
    uint8_t data[max_block], value[max_block];
    int error = 0;
    while (consumed < length - first) {
        error = read(position, data);
        if (error)
            break;
        position = next(position);
        consumed++;
        if (get(data) != magic || get(data + 8) != id)
            break;
        uint32_t type = get(data + 4);
        if (type == descriptor) {
            unsigned offset = 12;
            bool last = false;
            while (offset + 8 <= io.block_size) {
                uint32_t block = get(data + offset), flags = get(data + offset + 4);
                offset += 8;
                if (flags & ~(escape | same_uuid | last_tag)) {
                    error = -95;
                    break;
                }
                if (!(flags & same_uuid)) {
                    if (offset + 16 > io.block_size || memcmp(data + offset, header + 48, 16)) {
                        error = -117;
                        break;
                    }
                    offset += 16;
                }
                if (!target(block) || consumed == length - first) {
                    error = -117;
                    break;
                }
                if (pending_count == max_replay) {
                    error = -12;
                    break;
                }
                error = read(position, value);
                if (error || ((flags & escape) && get(value))) {
                    if (!error)
                        error = -117;
                    break;
                }
                pending[pending_count++] = {block, position, bool(flags & escape)};
                position = next(position);
                consumed++;
                if (flags & last_tag) {
                    last = true;
                    break;
                }
            }
            if (!error && !last)
                error = -117;
        } else if (type == revoke) {
            uint32_t bytes = get(data + 12);
            if (!(get(header + 40) & 1) || bytes < 16 || bytes > io.block_size || bytes % 4)
                error = -117;
            for (unsigned offset = 16; !error && offset < bytes; offset += 4) {
                uint32_t block = get(data + offset);
                if (!target(block))
                    error = -117;
                else if (revoked_count == max_replay)
                    error = -12;
                else
                    revoked[revoked_count++] = block;
            }
        } else if (type == commit) {
            if (data[12] || data[13]) {
                error = -95;
                break;
            }
            for (unsigned index = 0; !error && index < pending_count; index++) {
                unsigned slot = 0;
                while (slot < plan_count && plan[slot].target != pending[index].target)
                    slot++;
                if (slot == max_replay)
                    error = -12;
                else {
                    if (slot == plan_count)
                        plan_count++;
                    plan[slot] = pending[index];
                }
            }
            for (unsigned index = 0; index < revoked_count; index++)
                for (unsigned slot = 0; slot < plan_count; slot++)
                    if (plan[slot].target == revoked[index]) {
                        plan[slot] = plan[--plan_count];
                        break;
                    }
            pending_count = revoked_count = 0;
            id++;
        } else
            error = -117;
        if (error)
            break;
    }
    release(pending);
    release(revoked);
    if (!error) {
        // Skip the first incomplete ID too: its descriptors or commit record
        // may remain on disk after the recovered log is marked empty.
        next_sequence = id + 1;
        scanned = true;
    } else
        plan_count = 0;
    return error;
}

int journal_stage(Journal* journal, int (*stage)(void*, uint32_t, const void*), void* context) {
    if (!journal || !stage || journal->retrying)
        return -22;
    journal->staged = false;
    int error = journal->scan();
    uint8_t data[max_block];
    for (unsigned index = 0; !error && index < journal->plan_count; index++) {
        const auto& row = journal->plan[index];
        error = journal->payload(row, data);
        if (!error)
            error = stage(context, row.target, data);
    }
    if (!error)
        journal->staged = true;
    return error;
}

int journal_checkpoint(Journal* journal) {
    if (!journal || !journal->scanned || !journal->staged || journal->retrying)
        return -22;
    if (!journal->start)
        return 0;
    uint8_t data[max_block];
    for (unsigned index = 0; index < journal->plan_count; index++) {
        const auto& row = journal->plan[index];
        int error = journal->payload(row, data);
        if (!error)
            error = journal->io.write(journal->io.context, row.target, data);
        if (error)
            return error;
    }
    int error = journal->io.flush(journal->io.context);
    if (!error)
        error = journal->super(journal->next_sequence, 0);
    if (!error) {
        journal->sequence = journal->next_sequence;
        journal->start = journal->plan_count = 0;
    }
    return error;
}

int journal_commit(Journal* journal, const JournalWrite* writes, size_t count) {
    if (!journal || (!writes && count))
        return -22;
    if (!count)
        return journal->retrying ? -16 : 0;
    if (count > max_replay)
        return -12;
    unsigned tags = (journal->io.block_size - 28) / 8;
    uint64_t needed = count + (count + tags - 1) / tags + 1;
    if (needed > journal->length - journal->first)
        return -28;
    uint64_t hash = 14695981039346656037ull;
    for (size_t index = 0; index < count; index++) {
        if (!writes[index].data || !journal->target(writes[index].block))
            return -117;
        for (size_t previous = 0; previous < index; previous++)
            if (writes[previous].block == writes[index].block)
                return -22;
        hash = (hash ^ writes[index].block) * 1099511628211ull;
        auto bytes = static_cast<const uint8_t*>(writes[index].data);
        for (unsigned offset = 0; offset < journal->io.block_size; offset++)
            hash = (hash ^ bytes[offset]) * 1099511628211ull;
    }
    if (journal->retrying) {
        if (count != journal->retry_count || hash != journal->retry_hash)
            return -16;
    } else {
        if (journal->start)
            return -16;
        journal->retrying = true;
        journal->retry_count = count;
        journal->retry_hash = hash;
    }
    int error = journal->super(journal->sequence, journal->first);
    if (error)
        return error;
    uint32_t position = journal->first;
    uint8_t data[max_block], payload[max_block];
    for (size_t base = 0; base < count;) {
        size_t amount = min<size_t>(tags, count - base);
        memset(data, 0, journal->io.block_size);
        put(data, magic);
        put(data + 4, descriptor);
        put(data + 8, journal->sequence);
        unsigned offset = 12;
        for (size_t index = 0; index < amount; index++) {
            const auto& row = writes[base + index];
            unsigned flags = index ? same_uuid : 0;
            if (get(static_cast<const uint8_t*>(row.data)) == magic)
                flags |= escape;
            if (index + 1 == amount)
                flags |= last_tag;
            put(data + offset, row.block);
            put(data + offset + 4, flags);
            offset += 8;
            if (!index) {
                memcpy(data + offset, journal->header + 48, 16);
                offset += 16;
            }
        }
        error = journal->write(position, data);
        if (error)
            return error;
        position = journal->next(position);
        for (size_t index = 0; index < amount; index++) {
            memcpy(payload, writes[base + index].data, journal->io.block_size);
            if (get(payload) == magic)
                put(payload, 0);
            error = journal->write(position, payload);
            if (error)
                return error;
            position = journal->next(position);
        }
        base += amount;
    }
    error = journal->io.flush(journal->io.context);
    if (error)
        return error;
    memset(data, 0, journal->io.block_size);
    put(data, magic);
    put(data + 4, commit);
    put(data + 8, journal->sequence);
    error = journal->write(position, data);
    if (!error)
        error = journal->io.flush(journal->io.context);
    if (error)
        return error;
    for (size_t index = 0; index < count; index++) {
        error = journal->io.write(journal->io.context, writes[index].block, writes[index].data);
        if (error)
            return error;
    }
    error = journal->io.flush(journal->io.context);
    if (!error)
        error = journal->super(journal->sequence + 1, 0);
    if (!error) {
        journal->sequence++;
        journal->next_sequence = journal->sequence;
        journal->retrying = false;
        journal->scanned = true;
    }
    return error;
}
} // namespace ax
