#!/bin/sh
set -eu
printf '1\n' > /proc/sys/net/ipv6/conf/all/disable_ipv6
/bin/netlink-tests
echo AXIOM64_TESTS_PASS
