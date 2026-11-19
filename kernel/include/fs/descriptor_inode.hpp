// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    kernel/include/fs/descriptor_inode.hpp
 * @brief   VFS identities for pipes, sockets, and anonymous descriptors.
 * @author  frankischilling
 * @date    2026-11-19
 *
 * Declares the metadata and lifetime operations used by descriptor stat and
 * by procfs when a descriptor has no named filesystem path.
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

namespace ax {
struct Handle;
struct Node;
struct Pipe;

int attach_pipe_inode(Pipe&, Handle& reader, Handle& writer);
int descriptor_inode(Handle&, Node*&);
const char* descriptor_inode_name(const Node*);
bool is_anonymous_pipe_inode(const Node*);
bool descriptor_inode_path_only(const Node*);
void retain_descriptor_inode(Node*);
void release_descriptor_inode(Node*);
} // namespace ax
