// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/fs/ext2/journal.cpp
 * @brief   ext2 journal processing.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Validates and replays supported journal records and manages filesystem
 * transaction state.
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
#include "fs/ext2/journal.hpp"
#include "core/base.hpp"
#include "core/crc.hpp"

namespace ax {
namespace {
constexpr uint32_t magic = 0xc03b3998, descriptor = 1, commit = 2, super_v2 = 4, revoke = 5;
constexpr unsigned escape = 1, same_uuid = 2, last_tag = 8, max_replay = 4096;
constexpr unsigned max_block = 4096;
constexpr unsigned feature_revoke = 1, feature_wide = 2, feature_v2 = 8, feature_v3 = 16;
constexpr unsigned uuid_offset = 48, uuid_bytes = 16, record_header = 12;
constexpr unsigned super_bytes = 1024, super_checksum = 252, commit_checksum = 16;
constexpr uint8_t empty_uuid[uuid_bytes]{};
enum class Checksum { none, v1, v2, v3 };

uint32_t get(const uint8_t* p) {
    return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) | (uint32_t(p[2]) << 8) | p[3];
}

void put(uint8_t* p, uint32_t value) {
    p[0] = value >> 24;
    p[1] = value >> 16;
    p[2] = value >> 8;
    p[3] = value;
}

uint32_t checksum_with_zero(uint32_t seed, const uint8_t* block, unsigned length, unsigned field) {
    constexpr uint8_t zero[4]{};
    uint32_t crc = crc32c(seed, block, field);
    crc = crc32c(crc, zero, sizeof(zero));
    return crc32c(crc, block + field + sizeof(zero), length - field - sizeof(zero));
}

struct Replay {
    uint32_t target, position, sequence, digest;
    bool escaped;
};
} // namespace

struct Journal {
    JournalStorage io;
    uint8_t header[max_block], *reserved;
    Replay* plan;
    uint32_t first, length, sequence, start, next_sequence;
    uint32_t checksum_seed;
    Checksum checksum;
    bool wide;
    unsigned plan_count, payload_limit;
    bool scanned, staged, retrying;
    uint64_t retry_hash;
    size_t retry_count;

    bool record_checksums() const {
        return checksum == Checksum::v2 || checksum == Checksum::v3;
    }

    unsigned tag_bytes() const {
        if (checksum == Checksum::v3)
            return 16;
        return 8 + (wide ? 4 : 0) + (checksum == Checksum::v2 ? 2 : 0);
    }

    unsigned record_end() const {
        return io.block_size - (record_checksums() ? 4 : 0);
    }

    unsigned tags_per_descriptor() const {
        return (record_end() - record_header - uuid_bytes) / tag_bytes();
    }

    uint32_t block_digest(uint32_t id, const uint8_t* data, bool escape_magic = false) const {
        uint8_t sequence_bytes[4];
        put(sequence_bytes, id);
        uint32_t seed = crc32c(checksum_seed, sequence_bytes, sizeof(sequence_bytes));
        return escape_magic ? checksum_with_zero(seed, data, io.block_size, 0)
                            : crc32c(seed, data, io.block_size);
    }

    uint32_t tag_digest(uint32_t digest) const {
        return checksum == Checksum::v2 ? digest & 0xffff : digest;
    }

    bool valid_record(const uint8_t* data, unsigned field) const {
        return get(data + field) == checksum_with_zero(checksum_seed, data, io.block_size, field);
    }

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
        if (record_checksums())
            put(header + super_checksum,
                checksum_with_zero(UINT32_MAX, header, super_bytes, super_checksum));
        int error = write(0, header);
        return error ? error : io.flush(io.context);
    }

    int payload(const Replay& row, uint8_t* data) const {
        int error = read(row.position, data);
        if (error)
            return error;
        if (checksum != Checksum::none && block_digest(row.sequence, data) != row.digest)
            return -117;
        if (row.escaped) {
            if (get(data) != 0)
                return -117;
            put(data, magic);
        }
        return 0;
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

unsigned journal_payload_limit(const Journal* journal) {
    return journal->payload_limit;
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
    uint32_t compatible = get(header + 36), incompatible = get(header + 40);
    unsigned modes = incompatible & (feature_v2 | feature_v3);
    if (get(header + 4) != super_v2 || (compatible & ~1u) ||
        (incompatible & ~(feature_revoke | feature_wide | feature_v2 | feature_v3)) ||
        modes == (feature_v2 | feature_v3) || (compatible && modes) || get(header + 44) ||
        header[80] != (modes ? 4 : 0) || get(header + 84)) {
        error = -95;
        journal_close(journal);
        return nullptr;
    }
    journal->checksum = modes == feature_v3   ? Checksum::v3
                        : modes == feature_v2 ? Checksum::v2
                        : compatible          ? Checksum::v1
                                              : Checksum::none;
    journal->wide = incompatible & feature_wide;
    if (journal->record_checksums() &&
        get(header + super_checksum) !=
            checksum_with_zero(UINT32_MAX, header, super_bytes, super_checksum)) {
        journal_close(journal);
        return nullptr;
    }
    journal->checksum_seed = crc32c(UINT32_MAX, header + uuid_offset, uuid_bytes);
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
    // Each descriptor carries a UUID on its first tag, and every transaction
    // needs a separate commit record.
    unsigned tags = journal->tags_per_descriptor();
    uint32_t available = journal->length - journal->first - 1;
    uint32_t remainder = available % (tags + 1);
    journal->payload_limit =
        min(max_replay, available / (tags + 1) * tags + (remainder ? remainder - 1 : 0));
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
    uint32_t transaction_crc = UINT32_MAX;
    bool damaged_payload = false;
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
            unsigned end = record_end(), tag_size = tag_bytes(), offset = record_header;
            if (record_checksums() && !valid_record(data, end)) {
                error = -117;
                break;
            }
            if (checksum == Checksum::v1)
                transaction_crc = crc32_be(transaction_crc, data, io.block_size);
            bool last = false;
            while (offset + tag_size <= end) {
                uint32_t block = get(data + offset), flags = get(data + offset + 4);
                uint32_t expected = 0;
                if (checksum == Checksum::v3)
                    expected = get(data + offset + 12);
                if (checksum == Checksum::v2) {
                    expected = flags >> 16;
                    flags &= 0xffff;
                }
                if ((wide || checksum == Checksum::v3) && get(data + offset + 8)) {
                    error = -117;
                    break;
                }
                offset += tag_size;
                if (flags & ~(escape | same_uuid | last_tag)) {
                    error = -95;
                    break;
                }
                if (!(flags & same_uuid)) {
                    // Internal journals can carry zero in the optional tag UUID.
                    // The journal superblock must still name the mounted volume.
                    if (offset + uuid_bytes > end ||
                        (memcmp(data + offset, header + uuid_offset, uuid_bytes) &&
                         memcmp(data + offset, empty_uuid, uuid_bytes))) {
                        error = -117;
                        break;
                    }
                    offset += uuid_bytes;
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
                if (error)
                    break;
                if ((flags & escape) && get(value)) {
                    if (checksum == Checksum::none) {
                        error = -117;
                        break;
                    }
                    damaged_payload = true;
                }
                uint32_t digest = checksum == Checksum::none ? 0 : block_digest(id, value);
                if (record_checksums() && tag_digest(digest) != expected)
                    damaged_payload = true;
                if (checksum == Checksum::v1)
                    transaction_crc = crc32_be(transaction_crc, value, io.block_size);
                pending[pending_count++] = {block, position, id, digest, bool(flags & escape)};
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
            unsigned end = record_end(), width = wide ? 8 : 4;
            uint32_t bytes = get(data + 12);
            if ((record_checksums() && !valid_record(data, end)) ||
                !(get(header + 40) & feature_revoke) || bytes < 16 || bytes > end ||
                (bytes - 16) % width)
                error = -117;
            for (unsigned offset = 16; !error && offset < bytes; offset += width) {
                uint32_t block = get(data + offset + width - 4);
                if ((wide && get(data + offset)) || !target(block))
                    error = -117;
                else if (revoked_count == max_replay)
                    error = -12;
                else
                    revoked[revoked_count++] = block;
            }
        } else if (type == commit) {
            if (checksum == Checksum::v1) {
                if (data[12] != 1 || data[13] != 4 ||
                    get(data + commit_checksum) != transaction_crc)
                    error = -117;
            } else if (data[12] || data[13]) {
                error = -95;
            } else if (record_checksums() && !valid_record(data, commit_checksum)) {
                error = -117;
            }
            // The descriptor can reach disk before its data. Uncommitted
            // payloads are irrelevant even if a crash left them torn or absent.
            if (error || damaged_payload) {
                error = error ? error : -117;
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
            transaction_crc = UINT32_MAX;
            damaged_payload = false;
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
    unsigned tags = journal->tags_per_descriptor();
    if (count > journal_payload_limit(journal))
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
    uint32_t transaction_crc = UINT32_MAX;
    for (size_t base = 0; base < count;) {
        size_t amount = min<size_t>(tags, count - base);
        memset(data, 0, journal->io.block_size);
        put(data, magic);
        put(data + 4, descriptor);
        put(data + 8, journal->sequence);
        unsigned offset = record_header;
        for (size_t index = 0; index < amount; index++) {
            const auto& row = writes[base + index];
            unsigned flags = index ? same_uuid : 0;
            auto bytes = static_cast<const uint8_t*>(row.data);
            if (get(bytes) == magic)
                flags |= escape;
            if (index + 1 == amount)
                flags |= last_tag;
            put(data + offset, row.block);
            uint32_t digest = journal->record_checksums()
                                  ? journal->block_digest(journal->sequence, bytes, flags & escape)
                                  : 0;
            put(data + offset + 4, flags | (journal->checksum == Checksum::v2 ? digest << 16 : 0));
            if (journal->checksum == Checksum::v3)
                put(data + offset + 12, digest);
            offset += journal->tag_bytes();
            if (!index) {
                memcpy(data + offset, journal->header + uuid_offset, uuid_bytes);
                offset += uuid_bytes;
            }
        }
        if (journal->record_checksums()) {
            unsigned field = journal->record_end();
            put(data + field, crc32c(journal->checksum_seed, data, journal->io.block_size));
        }
        if (journal->checksum == Checksum::v1)
            transaction_crc = crc32_be(transaction_crc, data, journal->io.block_size);
        error = journal->write(position, data);
        if (error)
            return error;
        position = journal->next(position);
        for (size_t index = 0; index < amount; index++) {
            memcpy(payload, writes[base + index].data, journal->io.block_size);
            if (get(payload) == magic)
                put(payload, 0);
            if (journal->checksum == Checksum::v1)
                transaction_crc = crc32_be(transaction_crc, payload, journal->io.block_size);
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
    if (journal->checksum == Checksum::v1) {
        data[12] = 1;
        data[13] = 4;
        put(data + commit_checksum, transaction_crc);
    } else if (journal->record_checksums()) {
        put(data + commit_checksum, crc32c(journal->checksum_seed, data, journal->io.block_size));
    }
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
