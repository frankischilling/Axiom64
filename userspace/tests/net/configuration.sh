#!/bin/sh
set -eu
"/bin/${AXIOM64_CONFIGURATION_PROGRAM:-configuration-tests}"
echo AXIOM64_TESTS_PASS
