# Smoke Tests

## Initial Setup

### Pre-requisites for running these smoke tests

  - sudo access: these tests use sudo to perform certain functions.

  - test block devices: You must have access to one more more block devices.

  - `/etc/nf-test-devices`: A file that names the raw block devices to be used
    for testing. The file should contain one block device special file name
    per line, for example:

        $ cat /etc/nf-test-devices
        /dev/nvme0n1
        /dev/nvme0n2

    All devices listed in `/etc/nf-test-devices` should be the same drive
    model. If unsure, use a single device.

### Optional Features

Some tests rely on a python script to calculate descriptive statistics (min,
max, mean, standard deviation, etc) from data stored in log files. These tests
will still run (and will not fail), but to get the descriptive stats you need
the following:

    sudo dnf install python3-devel
    pip3 install --user numpy
    pip3 install --user pandas

## Quick Guide

*WARNING*: running smoke tests *will* destroy data on the test block devices.

The smoke tests make use of the system installed binaries, so make sure that
all mpool, mpool-kmod, hse
whether that is through an rpm/deb or `make $buildtype install`.

All the smoke tests can be run using `make $buildtype smoke`.

If you are working on a certain test, and you don't want to run all the tests,
then you have two options:

- Run the `tests/smoke/smoke $testname` script. This will only execute
`$testname`. A list of test names is available through either the `-l` or `-ll`
options of `tests/smoke/smoke`.
- Run the specific test you are trying to execute in the `test/smoke/tests`
directory. An example test run would look like
`./tests/smoke/tests/simple_client1`.

When executing the smoke tests through `meson`, the logs will output to
`builds/$hostname/rpm/$buildtype/smokelogs`. Otherwise logs will be placed in
`~/smokelogs`.

For more information about the smoke tests suite, check out
`test/smoke/smoke -h`.
