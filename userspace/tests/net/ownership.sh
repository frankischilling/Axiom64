#!/bin/sh
set -e
root=/tmp
if [ "$OWNERSHIP_VOLUME" = ext2 ]; then
    /bin/busybox mount -t ext2 /dev/vda /data
    /bin/busybox cmp /data/seed.txt /etc/ownership-seed
    root=/data
fi
/bin/ownership-tests "$root/owner-static"
/bin/ownership-dynamic "$root/owner-dynamic"
/bin/busybox sync
if [ "$OWNERSHIP_VOLUME" = ext2 ]; then
    /bin/busybox cmp /data/seed.txt /etc/ownership-seed
    /bin/busybox umount /data
    echo OWNERSHIP_UNMOUNT_PASS
fi
echo "OWNERSHIP_VOLUME_PASS volume=$OWNERSHIP_VOLUME"
echo AXIOM64_TESTS_PASS
