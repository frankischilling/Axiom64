#!/bin/sh
set -e
# These cohorts own their manual addresses and DAD packets. Match the native
# fixture before its readiness barrier while retaining the normal DAD interval.
printf '1\n' > /proc/sys/net/ipv6/conf/all/addr_gen_mode
for scope in /proc/sys/net/ipv6/conf/*; do
    printf '0\n' > "$scope/accept_ra"
    printf '0\n' > "$scope/autoconf"
    printf '0\n' > "$scope/enhanced_dad"
    printf '0\n' > "$scope/router_solicitations"
done
printf '1\n' > /proc/sys/net/ipv6/conf/all/disable_ipv6
printf '0\n' > /proc/sys/net/ipv6/conf/all/disable_ipv6
/bin/"$AXIOM64_IPV6_PROGRAM"
echo AXIOM64_TESTS_PASS
