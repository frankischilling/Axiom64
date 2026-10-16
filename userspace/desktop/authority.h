// SPDX-License-Identifier: GPL-3.0-or-later
#ifndef AXIOM64_DESKTOP_AUTHORITY_H
#define AXIOM64_DESKTOP_AUTHORITY_H

#include <stdint.h>

// Write one local MIT-MAGIC-COOKIE-1 authority record. The caller supplies a
// newly created private file and an initialized 128-bit secret; no cookie is logged.
int desktop_authority_write(int descriptor, unsigned display, const uint8_t cookie[16]);

// Read a single bounded record from a regular file without following symlinks.
// Invalid/truncated records fail before the caller sends any authorization bytes.
int desktop_authority_read(const char* path, unsigned display, uint8_t cookie[16]);

#endif
