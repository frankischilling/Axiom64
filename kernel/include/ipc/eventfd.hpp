// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "core/base.hpp"

namespace ax {
struct Eventfd;
struct Handle;

Handle* open_eventfd(uint32_t initial, bool semaphore, bool nonblocking, int& error);
void close_eventfd(Eventfd*);
bool eventfd_ready(const Eventfd*, bool write);
int64_t eventfd_read(Eventfd*, void*, size_t);
int64_t eventfd_write(Eventfd*, const void*, size_t);
} // namespace ax
