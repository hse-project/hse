# Contributing to HSE

We are currently focused on collaborating with the open source community to
get HSE and its related components into popular Linux distributions,
and are not able to accept contributions at this time.
However, see the [HSE Wiki](https://github.com/hse-project/hse/wiki)
for how you can report a bug, make a feature request, provide feedback,
or ask a question.

## Code Style

All the C code within HSE conforms to the defined `clang-format` file. All
Python code you may find in the code base conforms entirely to the `black`
formatter. For Meson files, try to match the style in other files, but most
importantly please use 4 spaces for indention rather than tabs.

Please make sure all contributions adhere to the aforementioned
styles.

## Cloning

You can clone HSE through both HTTPS and SSH protocols.

```sh
# HTTPS
git clone https://github.com/hse-project/hse.git
# SSH
git clone git@github.com:hse-project/hse.git
```

## Git Hooks

HSE has some Git hooks in its source tree that you are welcome to use.

```shell
ninja -C build git-hooks
# or
./scripts/dev/git-hooks
```

Either of the above commands will ensure that git hooks are properly setup for
the project.

## Building

HSE uses the [Meson build system](https://mesonbuild.com). You can obtain a copy
of `meson` from PyPI or through your system repositories. HSE currently needs a
copy of Meson >= 0.57 to build. If you choose to install from PyPI, it might
make sense to just install Meson into a [virtual environment](#Python).

```sh
# From PyPI
python3 -m pip install meson
```

Basic steps to build the project are the following:

```sh
meson build
ninja -C build # or 'meson compile -C build'
```

### Sanitized Builds

Meson has built-in support for sanitized builds.

Run `meson configure $builddir` to see what options exist for `b_sanitize`. It
is important to reduce issues like memory leaks and undefined behavior when
developing HSE. Common sanitizers you may want to use during development are
`address` and `undefined`.

## Installing

After building HSE, it can be installed using the following:

```sh
ninja -C build install # or 'meson install -C build'
```

You can configure where Meson installs the build artifacts using various
built-in configuration options for Meson.

### Uninstalling

If HSE was installed using Meson, then you can run the following to uninstall:

```sh
ninja -C build uninstall
```

## Testing

Test can be ran using the following:

```sh
meson test -C build [testname...]
```

In the event the tests timeout, you can change Meson's timeout multiplier
through the `-t` option.

```sh
meson test -C build -t 9 ikvdb_test
```

If you choose to add a feature or a bug fix to HSE, make sure to add any
necessary tests to confirm that the contribution works as it should.

### Suites

HSE has the following test suites:

- `unit` - unit tests
- `c0` - c0 tests
- `cn` - cn tests
- `framework` - test framework tests
- `kvdb` - kvdb tests
- `kvs` - kvs tests
- `util` - util tests
- `functional` - check HSE's functionality
- `smoke` - smoke tests

To run a full suite, run the following:

```sh
# If running multiple suites, use a comma separated list
meson test -C build --suite [suite...]
```

To execute only tests pertaining to `c0`, run the following:

```sh
meson test -C build --suite c0
```

The default test setup for HSE will run *all* test suites.

## Targets

Targets that you may find useful during HSE development:

- `install`
- `uninstall`
- `format`
- `python-repl`
- `shell`
- `test`
- `git-hooks`

```sh
ninja -C build [target...]
```

To format all code and source files for instance, run the following:

```sh
ninja -C build format
```

## Distributing

### Source

If you want to distribute HSE as a source tarball, then the following commands
should create a tar file in `build/meson-dist`.

```sh
# Read `meson dist -h` for other format options. Tests are disabled as an
# example, but you may want the test suites to run.
meson dist -C build --formats gz --no-tests
```

### Binary

If you want to distribute HSE as a binary tarball, then the following commands
should build a tar file where `--destdir` is specified.

```sh
meson install -C build --destdir /tmp/hse
cd /tmp
tar -czf hse.tar.gz hse
```

## Python

Some of the tests or tools may require various Python dependencies including
[`hse-python`](https://github.com/hse-project/hse-python). At the root of the
repository is a `requirements.txt`. If you are choosing to use a virtual
environment, then use the following steps to set one up properly.

```shell
# CWD = repository root
python3 -m venv venv
source venv/bin/activate
python3 -m pip install -r requirements.txt

# To exit the virtual environment
deactivate
```

After the virtual environment has been setup properly, then any errors which
you may have seen in previous attempts to build/test/install `hse` should be
resolved, at least partially.
