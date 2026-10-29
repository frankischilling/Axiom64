#!/bin/sh
set -e
printf '1\n' > /proc/sys/net/ipv6/conf/all/addr_gen_mode
/bin/dhcp-transport-tests
echo AXIOM64_TESTS_PASS
