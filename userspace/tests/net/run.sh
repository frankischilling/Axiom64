#!/bin/sh
set -eu
case "${AXIOM64_PHASE:-verify}" in
    queue) /bin/net-tests 65570 ;;
    error) /bin/net-tests fault-length ;;
    invalid) /bin/net-tests fault-id ;;
    *) /bin/net-tests 16 ;;
esac
echo AXIOM64_TESTS_PASS
