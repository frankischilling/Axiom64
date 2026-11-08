// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once
#include "ipc/ipc.hpp"

namespace ax {
// Private to IPC: allocation/close and namespace lookup share this bounded pool.
extern Socket sockets[256];
} // namespace ax
