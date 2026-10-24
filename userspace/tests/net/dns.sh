#!/bin/sh
set -eu
echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6
/bin/dns-static
/bin/dns-dynamic
echo AXIOM64_TESTS_PASS
