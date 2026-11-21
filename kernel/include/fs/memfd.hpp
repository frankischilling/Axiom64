// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/fs/memfd.hpp
 * @brief   Anonymous memory files and their virtual mappings.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Declares memory file creation, sealing, and mapping lifetime operations.
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
struct Handle;
struct Node;
struct Task;

bool is_memfd(const Node*);
int64_t memfd_create(Task&, uint64_t name, uint32_t flags);
int64_t memfd_fcntl(Handle&, unsigned command, uint32_t seals);
int memfd_fallocate(Task&, Handle&, unsigned mode, uint64_t offset, uint64_t length);
int memfd_write_limit(const Node*, uint64_t offset, size_t& length);
void memfd_open(Node*);
void memfd_close(Node*);
void memfd_reap(Node*);

int memfd_map(Task&, Handle&, uint64_t base, size_t length, uint64_t offset, int prot, bool shared,
              bool replace);
void memfd_link_mapping(FileMapping&);
void memfd_unlink_mapping(FileMapping&);
uint64_t memfd_page_protection(uint64_t entry, int prot);

enum class MemfdFault { outside, protection, bus, resolved };
MemfdFault memfd_fault(AddressSpace&, uint64_t address, bool write, bool execute);
} // namespace ax
