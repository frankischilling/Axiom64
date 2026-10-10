// SPDX-License-Identifier: GPL-3.0-or-later
#include "net/tcp/time_wait.hpp"
#include <cassert>
#include <cstdio>

using namespace ax::tcp;
static_assert(sizeof(TimeWait) <= 32);

static TimeWait original() {
    return {0x12345678, 0xfffffff0, 32768, 120000};
}

int main() {
    auto state = original();
    Segment segment{};
    segment.sequence = state.receive;
    segment.acknowledgment = state.send;
    segment.flags = ack;
    assert(time_wait_input(state, segment, 1) == TimeWaitAction::ignore);
    assert(state.deadline == 120000);
    segment.acknowledgment++;
    assert(time_wait_input(state, segment, 2) == TimeWaitAction::acknowledge);
    segment.acknowledgment = state.send - 1;
    assert(time_wait_input(state, segment, 3) == TimeWaitAction::ignore);
    segment.flags = fin | ack;
    segment.sequence = state.receive - 1;
    assert(time_wait_input(state, segment, 4000) == TimeWaitAction::acknowledge);
    assert(state.deadline == 124000);
    segment.flags = rst;
    assert(time_wait_input(state, segment, 5000) == TimeWaitAction::ignore);
    segment.sequence = state.receive + 1;
    assert(time_wait_input(state, segment, 5001) == TimeWaitAction::acknowledge);
    segment.sequence = state.receive;
    assert(time_wait_input(state, segment, 5002) == TimeWaitAction::remove);
    state = original();
    segment.flags = ack;
    segment.sequence = state.receive + state.window;
    assert(time_wait_input(state, segment, 1) == TimeWaitAction::acknowledge);
    segment.flags = rst;
    assert(time_wait_input(state, segment, 2) == TimeWaitAction::ignore);
    state.window = 0;
    segment.sequence = state.receive;
    segment.flags = ack;
    segment.acknowledgment = state.send;
    assert(time_wait_input(state, segment, 3) == TimeWaitAction::ignore);
    segment.flags = fin | ack;
    segment.sequence--;
    assert(time_wait_input(state, segment, 4) == TimeWaitAction::acknowledge);
    assert(state.deadline == 120004);
    segment.flags = syn;
    assert(time_wait_input(state, segment, 5) == TimeWaitAction::acknowledge);
    state = original();
    uint8_t byte = 1;
    segment = {};
    segment.sequence = state.receive;
    segment.acknowledgment = state.send;
    segment.flags = ack;
    segment.payload = &byte;
    segment.length = 1;
    assert(time_wait_input(state, segment, 1) == TimeWaitAction::acknowledge);
    assert(state.receive == 0xfffffff0); // Text past completed EOF is never accepted.
    segment.payload = nullptr;
    assert(time_wait_input(state, segment, 2) == TimeWaitAction::ignore);
    segment.length = maximum_segment_size + 1;
    assert(time_wait_input(state, segment, 3) == TimeWaitAction::ignore);
    segment.length = 0;
    assert(time_wait_input(state, segment, 119999) == TimeWaitAction::ignore);
    assert(time_wait_input(state, segment, 120000) == TimeWaitAction::remove);
    state = original();
    state.deadline = UINT64_MAX;
    segment.sequence = state.receive - 1;
    segment.flags = fin | ack;
    assert(time_wait_input(state, segment, UINT64_MAX - 10) == TimeWaitAction::acknowledge);
    assert(state.deadline == UINT64_MAX);
    assert(time_wait_input(state, segment, UINT64_MAX) == TimeWaitAction::remove);
    std::printf(
        "TCP_TIME_WAIT_PASS bytes=%zu duplicate_fin reset_filter wrap zero_window expiry bounds\n",
        sizeof(TimeWait));
}
