# HSE Smoke Tests

To run HSE smoke tests, you must first create a test mpool that can be
used with out root privileges.  Here is an example command sequence
that creates an mpool named "mptest".

    sudo mpool scan --deactivate
    sudo mpool destroy mptest
    sudo pvcreate /dev/nvme0n1
    sudo vgcreate -y mptest /dev/nvme0n1
    sudo lvcreate -y -l '100%FREE' -n mptest  mptest /dev/nvme0n1
    sudo mpool create -f mptest /dev/mptest/mptest uid=$(id -u) gid=$(id -g)
    sudo mpool activate mptest
    sudo mpool list mptest

If you created the mpool with "uid" and "gid" as shown above, you
should not need root access to create the KVDB or run the smoke tests.

Configure the build with tests enabled and set to use the test KVDB:

    meson configure build -Dtests=all -Dtests-kvdb=mptest

Build:

    meson compile -C build

Run the smoke tests:

    meson -C build --suite functional,smoke
