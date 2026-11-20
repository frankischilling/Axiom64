// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    userspace/tests/toolchain/shared.cpp
 * @brief   Verify guest-built shared C++ code from a separate executable.
 * @author  frankischilling
 * @date    2026-11-20
 *
 * Loads the guest-built library and checks exception unwinding across the
 * library boundary and independence of its thread-local state.
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
#include <cstdio>
#include <cstring>
#include <dlfcn.h>
#include <stdexcept>
#include <thread>

using LibraryStep = int (*)(int);

static bool check_thread(LibraryStep step, int increment) {
    if (step(increment) != 7 + increment || step(1) != 8 + increment)
        return false;
    try {
        step(-1);
    } catch (const std::runtime_error& error) {
        return std::strcmp(error.what(), "shared library exception") == 0;
    }
    return false;
}

int main(int argc, char** argv) {
    if (argc != 2)
        return 1;
    void* library = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!library) {
        std::fprintf(stderr, "dlopen: %s\n", dlerror());
        return 1;
    }
    auto step = reinterpret_cast<LibraryStep>(dlsym(library, "native_library_step"));
    if (!step) {
        std::fprintf(stderr, "dlsym: %s\n", dlerror());
        return 1;
    }

    bool initial = check_thread(step, 3);
    bool secondary = false;
    std::thread worker([&] { secondary = check_thread(step, 8); });
    worker.join();
    bool preserved = step(0) == 11;
    int closed = dlclose(library);
    if (!initial || !secondary || !preserved || closed != 0) {
        std::fputs("shared C++ exceptions or thread-local state failed\n", stderr);
        return 1;
    }
    std::puts("NATIVE_SHARED_CPP_PASS");
    return 0;
}
