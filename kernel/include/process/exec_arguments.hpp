// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/process/exec_arguments.hpp
 * @brief   Executable argument import interface.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Defines the bounds and storage used when importing argument and environment
 * vectors for exec.
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
#pragma once
#include "core/base.hpp"

namespace ax {
constexpr size_t exec_argument_limit = 6 * 1024 * 1024;
constexpr size_t exec_string_limit = 32 * page_size; // Includes the terminating NUL.
constexpr size_t exec_path_limit = 1024;             // Matches the current VFS path representation.
constexpr size_t exec_filename_limit = exec_path_limit + 24;

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
    int capture_named(Read, void*, const char* filename, uint64_t argv, uint64_t envp,
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
    char path_[exec_filename_limit]{};
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
    int capture_user_vectors(Read, void*, uint64_t argv, uint64_t envp);
};
} // namespace ax
