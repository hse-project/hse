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
formatter. Please make sure all contributions adhere to the aforementioned
styles.

## Building

HSE uses the [Meson build system](https://mesonbuild.com).

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

If you choose to add a feature or a bug fix to HSE, make sure to add any
necessary tests to confirm that the contribution works as it should.

### Suites

HSE has the following test suites:

- `unit` - run all unit tests
- `c0` - run all c0 tests
- `cn` - run all cn tests
- `framework` - run all test framework tests
- `kvdb` - run all kvdb tests
- `kvs` - run all kvs tests
- `util` - run all util tests

## Targets

Targets that you may find useful during HSE development:

- `install`
- `uninstall`
- `clang-format`
- `black`
- `python`
- `test`

## Python

Some of the tests or tools may require various Python dependencies including
[`hse-python`](https://github.com/hse-project/hse-python). At the root of the
repository is a `requirements.txt`. If you are choosing to use a virtual
environment, then use the following steps to set one up properly.

```shell
# CWD = repository root
# Recommend putting the venv in the build directory
python3 -m venv build/venv
source build/venv/bin/activate
python3 -m pip install -r requirements.txt

# To exit the virtual environment
deactivate
```

After the virtual environment has been setup properly, then any errors which
you may have seen in previous attempts to build/test/install `hse` should be
resolved, at least partially.
