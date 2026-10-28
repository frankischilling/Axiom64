#!/bin/sh
set -eu
/bin/ipv4-multicast-source-capacity-static
echo "[network] configured source limit and atomic bulk admission complete"
echo AXIOM64_TESTS_PASS
