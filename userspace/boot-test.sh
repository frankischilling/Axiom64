#!/bin/sh
set -eu
/bin/abi-static
/bin/abi-dynamic
/bin/ipc-tests
/bin/signal-tests
/bin/vfs-tests
echo 'BUSYBOX_ASH_STARTED'
uname -a
printf 'alpha\nbeta\n' > /tmp/shell-data
test "$(cat /tmp/shell-data | wc -l)" -eq 2
test "$(printf 'hello world' | tr a-z A-Z)" = 'HELLO WORLD'
mkdir /tmp/shell-dir
cp /tmp/shell-data /tmp/shell-dir/copy
cmp /tmp/shell-data /tmp/shell-dir/copy
rm /tmp/shell-dir/copy
rmdir /tmp/shell-dir
/bin/busybox sh -c 'exit 7' && exit 1 || test "$?" -eq 7
echo 'BUSYBOX_SHELL_PASS'
if test "${AXIOM64_SUITE:-full}" = abi; then
    echo AXIOM64_TESTS_PASS
    exit 0
fi
gcc --version
as --version
ld --version
make -C /root/toolchain-test test
echo 'NATIVE_TOOLCHAIN_PASS'
/bin/busybox sh /etc/desktop-test.sh
