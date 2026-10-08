// SPDX-License-Identifier: GPL-3.0-or-later
#include "net/manager/ownership.hpp"
#include "net/config/saved.hpp"
#include <errno.h>
#include <unistd.h>

namespace ax::net {
Ownership::~Ownership() {
    close();
}

int Ownership::open(const char* runtime) {
    if (descriptor_ >= 0)
        return EALREADY;
    return saved::lock(runtime, "manager.lock", descriptor_);
}

int Ownership::close() {
    int descriptor = descriptor_;
    descriptor_ = -1;
    return descriptor >= 0 && ::close(descriptor) < 0 ? errno : 0;
}
} // namespace ax::net
