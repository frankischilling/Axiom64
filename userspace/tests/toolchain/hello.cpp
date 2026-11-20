// SPDX-License-Identifier: GPL-3.0-or-later
/**
 * @file    userspace/tests/toolchain/hello.cpp
 * @brief   Guest C++ toolchain smoke test.
 * @author  frankischilling
 * @date    2026-11-18
 *
 * Provides a small C++ program to compile, link, and execute on the guest.
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
#include <iostream>
#include <numeric>
#include <stdexcept>
#include <vector>

int main() {
    std::vector<int> values{1, 2, 3, 4, 5};
    if (std::accumulate(values.begin(), values.end(), 0) != 15)
        return 1;
    try {
        throw std::runtime_error("C++ exception");
    } catch (const std::runtime_error& error) {
        if (std::string(error.what()) != "C++ exception")
            return 2;
    }
    std::cout << "NATIVE_CPP_PASS\n";
}
