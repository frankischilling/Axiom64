#!/bin/sh
set -e
root=/tmp
if [ "$PROFILE_VOLUME" = ext2 ]; then
    /bin/busybox mount -t ext2 /dev/vda /data
    /bin/busybox cmp /data/seed.txt /etc/profile-seed
    root=/data
fi
/bin/abi-static
/bin/abi-dynamic
/bin/profile-privacy-tests "$root/profile-static"
/bin/profile-privacy-dynamic "$root/profile-dynamic"
/bin/busybox rmdir "$root/profile-static" "$root/profile-dynamic"
/bin/busybox sync
if [ "$PROFILE_VOLUME" = ext2 ]; then
    /bin/busybox cmp /data/seed.txt /etc/profile-seed
    /bin/busybox umount /data
    echo PROFILE_PRIVACY_UNMOUNT_PASS
fi
echo "PROFILE_PRIVACY_VOLUME_PASS volume=$PROFILE_VOLUME"
echo AXIOM64_TESTS_PASS
