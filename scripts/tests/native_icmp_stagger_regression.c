// SPDX-License-Identifier: GPL-3.0-or-later
#define _GNU_SOURCE
#include <pthread.h>

static int delayed_barrier_wait(pthread_barrier_t* value);
static int observed_thread_create(pthread_t* thread, const pthread_attr_t* attributes,
                                  void* (*start)(void*), void* argument);

// Exercise the production writer with a real scheduler delay after its start
// barrier. Both writes use real pipes, complete payloads and monotonic clocks.
#define pthread_barrier_wait delayed_barrier_wait
#define pthread_create observed_thread_create
#define main native_control_main
#include "native_icmp_budget.c"
#undef main
#undef pthread_create
#undef pthread_barrier_wait

static _Thread_local struct lane* observed_lane;
static _Thread_local unsigned observed_waits;
static struct lane* observed_lanes[2];
static unsigned long first_writer_delay_ns;

static void* observed_start(void* argument) {
    observed_lane = argument;
    return inject(argument);
}

static int observed_thread_create(pthread_t* thread, const pthread_attr_t* attributes,
                                  void* (*start)(void*), void* argument) {
    struct lane* lane = argument;
    require(start == inject && lane->index < 2, "actual packet writer regression seam");
    observed_lanes[lane->index] = lane;
    return pthread_create(thread, attributes, observed_start, argument);
}

static int delayed_barrier_wait(pthread_barrier_t* value) {
    int code = pthread_barrier_wait(value);
    if (observed_lane && ++observed_waits == 2 && observed_lane->index == 0 &&
        observed_lanes[1]->target > observed_lanes[0]->target && first_writer_delay_ns) {
        struct timespec delay = {0, (long)first_writer_delay_ns};
        require(!nanosleep(&delay, NULL), "controlled first writer scheduler delay");
    }
    return code;
}

int main(int argc, char** argv) {
    require(argc == 2, "explicit regression scheduler delay");
    char* end = NULL;
    first_writer_delay_ns = strtoul(argv[1], &end, 10);
    require(end && !*end && first_writer_delay_ns <= 20000000,
            "bounded regression scheduler delay");
    cpu_set_t mask;
    require(!sched_getaffinity(0, sizeof(mask), &mask), "native CPU inventory");
    int cpus[2] = {-1, -1};
    for (int at = 0; at < CPU_SETSIZE; at++)
        if (CPU_ISSET(at, &mask)) {
            if (cpus[0] < 0)
                cpus[0] = at;
            else {
                cpus[1] = at;
                break;
            }
        }
    require(cpus[1] >= 0, "two native writer CPUs");
    struct lane lanes[2] = {{.cpu = cpus[0]}, {.cpu = cpus[1], .index = 1}};
    int descriptors[2][2];
    for (unsigned at = 0; at < 2; at++) {
        require(!pipe(descriptors[at]), "real writer regression pipe");
        lanes[at].fd = descriptors[at][1];
        for (unsigned byte = 0; byte < sizeof(lanes[at].frame); byte++)
            lanes[at].frame[byte] = (unsigned char)(byte + at);
    }
    inject_pair(lanes, 0);
    for (unsigned at = 0; at < 2; at++) {
        unsigned char received[60];
        require(read(descriptors[at][0], received, sizeof(received)) == sizeof(received) &&
                    !memcmp(received, lanes[at].frame, sizeof(received)),
                "both actual writer payloads arrive unchanged");
        close(descriptors[at][0]);
        close(descriptors[at][1]);
    }
    int64_t gap = (int64_t)lanes[1].before - (int64_t)lanes[0].after;
    printf("{\"actual_gap_after_first_write_ns\":%lld,\"first_before_ns\":%llu,"
           "\"first_after_ns\":%llu,\"second_before_ns\":%llu,\"second_after_ns\":%llu,"
           "\"real_complete_payloads\":2}\n",
           (long long)gap, (unsigned long long)lanes[0].before, (unsigned long long)lanes[0].after,
           (unsigned long long)lanes[1].before, (unsigned long long)lanes[1].after);
    return gap >= 1000000 ? 0 : 1;
}
