<!--
SPDX-License-Identifier: Apache-2.0 OR MIT

SPDX-FileCopyrightText: Copyright 2020 Micron Technology, Inc.
-->

# Contributing to the HSE Project

We welcome your contributions to the HSE project.

The first section below contains general information on contributing to
the HSE project. It is referenced by the `CONTRIBUTING.md` files in all
other HSE project repos.

The second section contains information on contributing to this specific repo.

## General Information on Contributing

### Prior to Starting Work

* Review the [RFC process](https://github.com/hse-project/rfcs) to determine
if the work you are planning requires an RFC.
* Use the `Ideas` category of the HSE
[discussions forum](https://github.com/hse-project/hse/discussions)
to get feedback on minor features or enhancements not requiring an RFC.
* File an issue in the appropriate repo using the predefined templates.

### Submitting a Pull Request

* Submit pull requests (PRs) following the GitHub
[fork and pull model](https://docs.github.com/en/github/collaborating-with-pull-requests/getting-started/about-collaborative-development-models#fork-and-pull-model).
* Commits must be signed-off which indicates that you agree to the
[Developer Certificate of Origin](https://developercertificate.org/).
This is done using the `--signoff` option when committing your changes.
* Initial commits must be rebased.
* Use the predefined PR template and specify which issue the commit
addresses, what the commit does, and provide a concise description of
the change.
* All new code must include unit or functional tests.
* All existing unit and functional tests must pass.
* For any data path changes, run the benchmark suite before and after
your PR to verify there is no regression.

### Coding Style

All the C code within HSE conforms to the pre-defined `clang-format` file. All
Python code you may find in the code base conforms entirely to the `black`
formatter. For Meson files, try to match the style in other files, but most
importantly use 4 spaces for indention rather than tabs.

Make sure all contributions adhere to the aforementioned styles.

## Information on Contributing to this Repo

### Cloning

You can clone HSE through both HTTPS and SSH protocols.

```sh
# HTTPS
git clone https://github.com/hse-project/hse.git
# SSH
git clone git@github.com:hse-project/hse.git
```

### Building

Refer to the [README.md](./README.md#building-hse) to get
started.

HSE comes with many build options. Refer to the
[`meson_options.txt` file](./meson_options.txt) for all available build options.
Alternatively run the following command after successfully configuring HSE:

```shell
meson configure build
```

#### For Distribution Maintainers

The following HSE-specific build options are recommended for distributing HSE:

```shell
meson setup build -Dbuildtype=release -Dexperimental=false -Dtools=disabled \
    -Dsamples=false -Dbindings=none
```

#### Sanitized Builds

Meson has built-in support for sanitized builds.

Run `meson configure build` to see what options exist for `b_sanitize`. It
is important to reduce issues like memory leaks and undefined behavior when
developing HSE. Common sanitizers you may want to use during development are
`address` and `undefined`.

HSE maintainers aim to have all tests pass with
`-Db_sanitize=address,undefined`. Keeping
that baseline is extremely important. All contributions will be required to meet
that same standard. Compiling with these options locally can help contributors
identify issues early on in their work.

#### Documentation

HSE's public API documentation is generated from the source code with Doxygen.
The following commands will generate static HTML in `build/docs/doxygen/output/html`.

```shell
meson setup build -Ddocs=enabled
meson compile -C build docs
```

A run target has also been provided to start a Python webserver that serves the
generated HTML. The server's port number is designated by the kernel unless the
environment variable `HSE_DOXYGEN_SERVE_PORT` is set to a port number.

```shell
meson compile -C build doxygen-serve
```

### Installing

Refer to the [README.md](./README.md#building-hse) to get
started.

Meson has various options for controlling where build artifacts will install to
if you need something other than the defaults.

### Uninstalling

If HSE was installed using Meson, then you can run the following to uninstall:

```shell
ninja -C build uninstall
```

If you also install subprojects, then those will also be uninstalled.

### Testing

If you choose to add a feature or a bug fix to HSE, make sure to add any
necessary tests to confirm that the contribution works as it should.

Tests can be run using the following:

```shell
meson test -C build [tests...]
```

We recommend running tests through Meson always. There is a lot of
infrastructure setup through Meson that you would have to duplicate otherwise.

#### Timeouts

Depending on the speed of your drive, tests may timeout frequently. We recommend
mounting a fast drive to run HSE tests. In order to tell HSE's test
infrastructure about your mounted drive, use the `HSE_TEST_RUNNER_DIR`
environment variable with that value set to the drive's mount point.

In the event tests do timeout, you can change Meson's timeout multiplier
through the `-t` option:

```shell
meson test -C build -t 9 [tests...]
```

#### Suites

To run a specific suite, run the following:

```shell
# If running multiple suites, use a comma separated list
meson test -C build [--suite suite...]
```

To ignore a suite, run the following:

```shell
# If running multiple suites, use a comma separated list
meson test -C build [--no-suite suite...]
```

#### GDB

Meson comes with built-in support for `gdb` using `--gdb` when running
`meson test`. When using this option with HSE tests, you will want to run the
following within `gdb`:

```text
set follow-fork-mode child
```

The HSE [test-runner](./tests/test-runner) will `fork(2)` the actual test.
Without the above command, you will not actually debug what you think you are.

#### Replicating CI Build Checks

The CI runs the builds on ubuntu and fedora system with release and
debugoptimized build types. To mimic the checks for build validation in CI run
the following:

```shell
meson build -Dbuildtype=${build_type} -Dwerror=true \
    -Db_sanitize=address,undefined
meson test -C build --setup=ci
```

### Distributing the Source

If you want to distribute HSE as a source tarball, then the following commands
should create a tar file in `build/meson-dist`.

```shell
# Read `meson dist -h` for other format options. Tests are disabled as an
# example, but you may want the test suites to run.
meson dist -C build --formats gz --no-tests
```

### Distributing Binaries

If you want to distribute HSE as a binary tarball, then the following commands
should build a tar file where `--destdir` is specified.

```sh
meson install -C build --destdir $location
cd $location
tar -czf hse.tar.gz hse
```

### Git Hooks

HSE has some Git hooks in its source tree that you are welcome to use.

```shell
ninja -C build git-hooks
# or
./scripts/dev/git-hooks
```

Either of the above commands will ensure that Git hooks are properly setup for
the project.

### Coverage

HSE uses `gcovr` to get code coverage. To enable coverage and get the coverage
reports run the following:

```shell
meson build --buildtype=debug -Db_coverage=true
meson compile -C build
meson test -C build --setup=ci
meson compile gcovr-{html,text,json,xml} -C build
```
