// SPDX-License-Identifier: GPL-3.0-or-later
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
