#!/bin/sh
set -eu
printf '1\n' > /proc/sys/net/ipv6/conf/all/addr_gen_mode
"${AXIOM64_MULTICAST_CLIENT:-/bin/ipv4-multicast-static}"
echo AXIOM64_TESTS_PASS
