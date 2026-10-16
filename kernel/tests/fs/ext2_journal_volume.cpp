// SPDX-License-Identifier: GPL-3.0-or-later
#include "fs/ext2/journal.hpp"
#include <cassert>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <map>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

namespace ax {
void* alloc(size_t size) {
    return std::malloc(size);
}

void release(void* pointer) {
    std::free(pointer);
}
} // namespace ax

using namespace ax;

namespace {
struct Disk {
    int fd = -1;
    unsigned size = 0, calls = 0, cut = 0;
    bool after = false;
    std::map<uint32_t, std::vector<uint8_t>> overlay;

    static int read(void* context, uint32_t block, void* data) {
        auto& disk = *static_cast<Disk*>(context);
        return pread(disk.fd, data, disk.size, off_t(block) * disk.size) == disk.size ? 0 : -5;
    }

    static int write(void* context, uint32_t block, const void* data) {
        auto& disk = *static_cast<Disk*>(context);
        bool selected = ++disk.calls == disk.cut;
        if (selected && !disk.after)
            return -5;
        if (pwrite(disk.fd, data, disk.size, off_t(block) * disk.size) != disk.size ||
            fdatasync(disk.fd))
            return -5;
        return selected ? -5 : 0;
    }

    static int flush(void* context) {
        auto& disk = *static_cast<Disk*>(context);
        bool selected = ++disk.calls == disk.cut;
        if (selected && !disk.after)
            return -5;
        int error = fsync(disk.fd) ? -5 : 0;
        return error ? error : selected ? -5 : 0;
    }

    static int stage(void* context, uint32_t block, const void* data) {
        auto& disk = *static_cast<Disk*>(context);
        const auto bytes = static_cast<const uint8_t*>(data);
        disk.overlay[block] = std::vector<uint8_t>(bytes, bytes + disk.size);
        return 0;
    }
};

uint32_t word(const uint8_t* p) {
    return uint32_t(p[0]) | (uint32_t(p[1]) << 8) | (uint32_t(p[2]) << 16) | (uint32_t(p[3]) << 24);
}

std::vector<uint8_t> bytes(const char* name) {
    auto input = fopen(name, "rb");
    assert(input && !fseek(input, 0, SEEK_END));
    long size = ftell(input);
    assert(size >= 0 && !fseek(input, 0, SEEK_SET));
    std::vector<uint8_t> result(size);
    assert(fread(result.data(), 1, result.size(), input) == result.size());
    assert(!ferror(input) && !fclose(input));
    return result;
}
} // namespace

int main(int argc, char** argv) {
    assert(argc == 5 || argc == 7);
    auto mapping = bytes(argv[3]);
    assert(mapping.size() >= 4096 && mapping.size() % 4 == 0);
    std::vector<uint32_t> map(mapping.size() / 4);
    for (unsigned index = 0; index < map.size(); index++)
        map[index] = word(mapping.data() + index * 4);
    Disk disk{};
    disk.fd = open(argv[2], O_RDWR | O_NOFOLLOW);
    struct stat info{};
    assert(disk.fd >= 0 && !fstat(disk.fd, &info) && S_ISREG(info.st_mode));
    uint8_t super[1024];
    assert(pread(disk.fd, super, sizeof(super), 1024) == sizeof(super));
    disk.size = 1024u << word(super + 24);
    assert(info.st_size % disk.size == 0);
    JournalStorage storage{&disk,
                           disk.size,
                           uint32_t(info.st_size / disk.size),
                           map.data(),
                           uint32_t(map.size()),
                           Disk::read,
                           Disk::write,
                           Disk::flush};
    int error;
    auto journal = journal_open(storage, super + 104, error);
    if (!journal) {
        fprintf(stderr, "EXT2_JOURNAL_VOLUME_OPEN_FAIL error=%d\n", error);
        assert(!close(disk.fd));
        return 1;
    }
    if (!strcmp(argv[1], "produce")) {
        auto input = bytes(argv[4]);
        assert(input.size() >= 4);
        uint32_t count = word(input.data());
        assert(count && count <= 4096 && input.size() == 4 + size_t(count) * (4 + disk.size));
        std::vector<JournalWrite> writes(count);
        for (unsigned index = 0; index < count; index++) {
            auto offset = 4 + size_t(index) * (4 + disk.size);
            writes[index] = {word(input.data() + offset), input.data() + offset + 4};
        }
        if (argc == 7) {
            disk.cut = unsigned(strtoul(argv[5], nullptr, 10));
            assert(!strcmp(argv[6], "before") || !strcmp(argv[6], "after"));
            disk.after = !strcmp(argv[6], "after");
        }
        error = journal_commit(journal, writes.data(), count);
        printf("EXT2_JOURNAL_VOLUME_PRODUCE result=%d calls=%u count=%u\n", error, disk.calls,
               count);
    } else {
        assert(!strcmp(argv[1], "recover") && argc == 5);
        error = journal_stage(journal, Disk::stage, &disk);
        assert(!error && !disk.calls);
        error = journal_checkpoint(journal);
        assert(!error);
        // An unmount clears the recovery flag only after the recovered home
        // blocks are durable. This is a separate one-block transaction.
        std::vector<uint8_t> block(disk.size);
        uint32_t number = 1024 / disk.size;
        assert(!Disk::read(&disk, number, block.data()));
        auto header = block.data() + 1024 % disk.size;
        header[96] &= ~4u;
        header[58] |= 1;
        JournalWrite clean{number, block.data()};
        assert(!journal_commit(journal, &clean, 1));
        printf("EXT2_JOURNAL_VOLUME_RECOVERY_PASS staged=%zu calls=%u\n", disk.overlay.size(),
               disk.calls);
    }
    journal_close(journal);
    assert(!close(disk.fd));
    return error ? 1 : 0;
}
