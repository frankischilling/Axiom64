#!/bin/sh
set -eu
/bin/dns-static
/bin/dns-dynamic
echo AXIOM64_TESTS_PASS
