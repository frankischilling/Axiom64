#!/bin/sh
set -eu
if test "${AXIOM64_PHASE:-none}" = cond; then
    /bin/thread-static cond
elif test "${AXIOM64_PHASE:-none}" = io; then
    failed=0
    /bin/thread-io-static --guest || failed=1
    /bin/thread-io-dynamic --guest || failed=1
    test "$failed" = 0
else
    /bin/thread-static
    /bin/thread-dynamic
    /bin/futex-static
    /bin/futex-dynamic
    /bin/lifecycle-static
    /bin/lifecycle-dynamic
    /bin/thread-io-static --guest
    /bin/thread-io-dynamic --guest
    g++ -std=c++20 -O2 -pthread /root/toolchain-test/threads.cpp -o /tmp/native-threads
    /tmp/native-threads
fi
echo AXIOM64_TESTS_PASS
