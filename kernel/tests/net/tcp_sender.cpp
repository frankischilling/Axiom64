// SPDX-License-Identifier: GPL-3.0-or-later
#include "net/tcp/sender.hpp"
#include <cassert>
#include <cstdio>

using namespace ax::tcp;

static void retransmission() {
    Retransmission timer;
    assert(timer.interval() == 1000);
    timer.sample(2000, false);
    assert(timer.interval() == 6000);
    timer.sample(1000, false);
    assert(timer.interval() == 5875); // Variation uses the old SRTT before updating it.
    timer.sample(1, true);
    assert(timer.interval() == 5875);
    timer.backoff();
    assert(timer.interval() == 11750);
    for (unsigned at = 0; at < 20; at++)
        timer.backoff();
    assert(timer.interval() == 60000);
    Retransmission handshake;
    handshake.backoff();
    handshake.established(true);
    assert(handshake.interval() == 3000);
    handshake.sample(100, false);
    assert(handshake.interval() == 1000);
    handshake.sample(UINT32_MAX, false);
    assert(handshake.interval() == 60000);
    Retransmission local;
    local.sample(0, false);
    assert(local.interval() == 1000);
    local.established(true);
    assert(local.interval() == 1000);
}

static void congestion() {
    Congestion control(1460);
    assert(control.window() == 4380);
    control.acknowledged(100);
    assert(control.window() == 4480);
    control.acknowledged(10000);
    assert(control.window() == 5940);
    assert(!control.duplicate(14600) && !control.duplicate(14600));
    assert(control.duplicate(14600));
    assert(control.recovery() && control.threshold() == 7300 && control.window() == 11680);
    assert(!control.duplicate(14600) && control.window() == 13140);
    control.acknowledged(1460);
    assert(!control.recovery() && control.window() == 7300);
    for (unsigned at = 0; at < 7299; at++)
        control.acknowledged(1);
    assert(control.window() == 7300);
    control.acknowledged(1);
    assert(control.window() == 8760);
    control.timeout(11680);
    assert(control.threshold() == 5840 && control.window() == 1460 && !control.recovery());
    control.acknowledged(1460);
    assert(control.window() == 2920);
    control.acknowledged(1460);
    control.acknowledged(1460);
    control.acknowledged(5840);
    assert(control.window() == 7300);
    control.idle();
    assert(control.window() == 4380);
    Congestion recovery(1460);
    recovery.duplicate(14600);
    recovery.duplicate(14600);
    assert(recovery.duplicate(14600));
    recovery.timeout(5840);
    assert(recovery.threshold() == 2920 && recovery.window() == 1460 && !recovery.recovery());
    recovery.timeout(2920, true);
    assert(recovery.threshold() == 2920); // Repeated RTO of the same oldest segment holds ssthresh.
    recovery.established(true);
    assert(recovery.window() == 1460);
    Congestion defaults;
    assert(defaults.window() == 2144);
    Congestion large(UINT32_MAX);
    assert(large.window() == 131070);
    for (unsigned at = 0; at < 50000; at++) {
        if (at % 37 == 0)
            large.timeout(UINT32_MAX);
        else if (at % 7 == 0)
            large.duplicate(UINT32_MAX);
        else
            large.acknowledged(UINT32_MAX);
        assert(large.window() && large.window() <= (1u << 30));
        assert(large.threshold() && large.threshold() <= (1u << 30));
    }
}

int main() {
    retransmission();
    congestion();
    std::puts("TCP_SENDER_PASS rtt_order karn_backoff syn_fallback slow_start byte_count recovery "
              "timeout bounds");
}
