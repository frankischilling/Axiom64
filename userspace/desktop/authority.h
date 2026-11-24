// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    userspace/desktop/authority.h
 * @brief   X11 authority interface.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Declares the operations that write and handle X11 authorization records.
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
#ifndef AXIOM64_DESKTOP_AUTHORITY_H
#define AXIOM64_DESKTOP_AUTHORITY_H

#include <stdint.h>

// Write one local MIT-MAGIC-COOKIE-1 authority record. The caller supplies a
// newly created private file and an initialized 128-bit secret; no cookie is logged.
int desktop_authority_write(int descriptor, unsigned display, const uint8_t cookie[16]);

// Read a single bounded record from a regular file without following symlinks.
// Invalid/truncated records fail before the caller sends any authorization bytes.
int desktop_authority_read(const char* path, unsigned display, uint8_t cookie[16]);

// Read the leading matching local record from the Xorg seat's authority file.
// SDDM also appends a wildcard record. The client only uses the local record.
int desktop_authority_read_local(const char* path, unsigned display, uint8_t cookie[16]);

#endif
