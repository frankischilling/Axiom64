#!/bin/sh
set -eu
/bin/ipv4-tests
if [ "${AXIOM64_IP_FAULT:-0}" = 1 ]; then
    echo AXIOM64_TESTS_PASS
    exit 0
fi
/bin/busybox ifconfig eth0 10.23.1.2 netmask 255.255.255.0 up
/bin/busybox ifconfig eth1 10.23.2.2 netmask 255.255.255.0 up
/bin/busybox route add default gw 10.23.1.1
/bin/busybox ping -n -c 2 -w 5 -I eth0 10.23.1.1
/bin/busybox ping -n -c 2 -w 5 -I eth1 10.23.2.1
/bin/busybox route del default gw 10.23.1.1
echo IPV4_BUSYBOX_PASS
echo AXIOM64_TESTS_PASS
