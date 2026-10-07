// SPDX-License-Identifier: GPL-3.0-or-later
#include <condition_variable>
#include <cstdio>
#include <mutex>
#include <thread>
#include <vector>

static std::mutex lock;
static std::condition_variable changed;
static unsigned items, produced, consumed;
static thread_local unsigned local = 7;

static void produce(unsigned number) {
    local = number + 20;
    for (unsigned i = 0; i < 800; ++i) {
        std::unique_lock<std::mutex> held(lock);
        changed.wait(held, [] { return items < 12; });
        if (local != number + 20)
            std::terminate();
        ++items;
        ++produced;
        changed.notify_all();
    }
}

static void consume() {
    for (unsigned i = 0; i < 800; ++i) {
        std::unique_lock<std::mutex> held(lock);
        changed.wait(held, [] { return items != 0; });
        --items;
        ++consumed;
        changed.notify_all();
    }
}

int main() {
    std::vector<std::thread> workers;
    for (unsigned i = 0; i < 3; ++i) {
        workers.emplace_back(produce, i);
        workers.emplace_back(consume);
    }
    for (auto& thread : workers)
        thread.join();
    if (items || produced != 2400 || consumed != 2400 || local != 7)
        return 1;
    std::unique_lock<std::mutex> held(lock);
    if (changed.wait_for(held, std::chrono::milliseconds(30)) != std::cv_status::timeout)
        return 1;
    std::puts("NATIVE_THREADS_PASS");
}
