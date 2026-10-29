#!/bin/sh
set -eu
/bin/ipv4-multicast-source-static
echo "[network] source-filter ABI complete"
echo AXIOM64_TESTS_PASS
