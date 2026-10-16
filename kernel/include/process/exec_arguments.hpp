// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "core/base.hpp"

namespace ax {
constexpr size_t exec_argument_limit = 6 * 1024 * 1024;
constexpr size_t exec_string_limit = 32 * page_size; // Includes the terminating NUL.
constexpr size_t exec_path_limit = 1024;             // Matches the current VFS path representation.

struct ExecStack {
    uint64_t bottom, top, strings, platform, filename, random, pointer;
    size_t mapping_size, auxiliary_size;
};

// Own every string and vector before preparing a replacement address space.
// Reads and writes are adapters so the same bounds and layout run in host tests.
class ExecArguments {
  public:
    using Read = bool (*)(void*, uint64_t, void*, size_t);
    using Write = bool (*)(void*, uint64_t, const void*, size_t);

    ExecArguments() = default;
    ~ExecArguments();
    ExecArguments(const ExecArguments&) = delete;
    ExecArguments& operator=(const ExecArguments&) = delete;

    int capture(Read, void*, uint64_t path, uint64_t argv, uint64_t envp,
                uint64_t stack_limit = UINT64_MAX);
    int capture_kernel(const char*, const char* const*, const char* const*,
                       uint64_t stack_limit = UINT64_MAX);

    const char* path() const {
        return path_;
    }

    size_t argc() const {
        return argc_;
    }

    size_t envc() const {
        return envc_;
    }

    const char* const* argv() const {
        return values_;
    }

    const char* const* envp() const {
        return values_ + argc_ + 1;
    }

    int layout(uint64_t top, size_t auxiliary_size, ExecStack&) const;
    int write_stack(const ExecStack&, Write, void*, const uint8_t random[16], const void* auxiliary,
                    size_t auxiliary_size) const;

  private:
    char path_[exec_path_limit]{};
    char* text_ = nullptr;
    const char** values_ = nullptr;
    size_t used_ = 0, capacity_ = 0, count_ = 0, vector_capacity_ = 0;
    size_t argc_ = 0, envc_ = 0, processed_ = 0, budget_ = 0;
    size_t limit_ = exec_argument_limit;
    uint64_t stack_limit_ = UINT64_MAX;
    bool ready_ = false;

    void clear();
    int append_pointer(const char*, bool charged);
    int append_bytes(const char*, size_t);
    int vector(Read, void*, uint64_t, const char* const*, size_t&);
    int string(Read, void*, uint64_t, const char*, size_t);
    int finish(Read, void*, bool kernel, bool empty);
};
} // namespace ax
