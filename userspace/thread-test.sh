#!/bin/sh
set -eu
if test "${AXIOM64_PHASE:-none}" = cond; then
    /bin/thread-static cond
else
    /bin/thread-static
    /bin/thread-dynamic
    /bin/futex-static
    /bin/futex-dynamic
    /bin/lifecycle-static
    /bin/lifecycle-dynamic
    g++ -std=c++20 -O2 -pthread /root/toolchain-test/threads.cpp -o /tmp/native-threads
    /tmp/native-threads
fi
echo AXIOM64_TESTS_PASS
