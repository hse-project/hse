# HSE Smoke Tests

First, ensure HSE has been built:

    ninja -C build

To run HSE smoke tests, you must first create a test mpool.  Here is
an example command sequence that creates an mpool named "mp1".

    sudo mpool scan --deactivate
    sudo mpool destroy mp1
    sudo pvcreate /dev/nvme0n1
    sudo vgcreate -y mp1 /dev/nvme0n1
    sudo lvcreate -y -l '100%FREE' -n mp1  mp1 /dev/nvme0n1
    sudo mpool create -f mp1 /dev/mp1/mp1 uid=$(id -u) gid=$(id -g)
    sudo mpool activate mp1
    sudo mpool list mp1

If you created the mpool with "uid" and "gid" as shown above, you
should not need root access to create the KVDB or run the smoke tests.

Create the test KVDB:

    hse1 kvdb create mp1

Run the smoke test, providing the build dir and the mpool name:

    ./tests/functional/smoke/smoke -C build -m mp1

To get more help:

    ./tests/functional/smoke/smoke -h

The tests take almost an hour to run a dual socket Intel Xeon E5-2690
2.60GHz server with 256G DRAM and a fast SSD (9200).
