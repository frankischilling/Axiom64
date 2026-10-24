#!/bin/sh
set -eu
printf '1\n' > /proc/sys/net/ipv6/conf/all/addr_gen_mode
/bin/udp-tests --wire
echo AXIOM64_TESTS_PASS
