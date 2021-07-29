# Contributing to the HSE Project

We welcome your contributions to the HSE project.

The first section below contains general information on contributing to
the HSE project.  It is referenced by the `CONTRIBUTING.md` files in all
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

All the C code within HSE conforms to the defined `clang-format` file. All
Python code you may find in the code base conforms entirely to the `black`
formatter. For Meson files, try to match the style in other files, but most
importantly please use 4 spaces for indention rather than tabs.

Please make sure all contributions adhere to the aforementioned
styles.


## Information on Contributing to this Repo

### Cloning

You can clone HSE through both HTTPS and SSH protocols.

```sh
# HTTPS
git clone https://github.com/hse-project/hse.git
# SSH
git clone git@github.com:hse-project/hse.git
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

### Building

HSE uses the [Meson build system](https://mesonbuild.com). You can obtain a copy
of `meson` from PyPI or through your system repositories. HSE currently needs a
copy of Meson >= 0.58 to build. If you choose to install from PyPI, it might
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

### Installing

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

### Testing

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

### Test Suites

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

The default test setup for HSE runs the unit test suite.

### Targets

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

### Distributing Source

If you want to distribute HSE as a source tarball, then the following commands
should create a tar file in `build/meson-dist`.

```sh
# Read `meson dist -h` for other format options. Tests are disabled as an
# example, but you may want the test suites to run.
meson dist -C build --formats gz --no-tests
```

### Distributing Binaries

If you want to distribute HSE as a binary tarball, then the following commands
should build a tar file where `--destdir` is specified.

```sh
meson install -C build --destdir /tmp/hse
cd /tmp
tar -czf hse.tar.gz hse
```

### Python

Some of the tests or tools may require various Python dependencies including
[`hse-python`](https://github.com/hse-project/hse-python). At the root of the
repository is a `pyproject.toml`, which is configured with Poetry to install 
python dependencies. Poetry will setup a virtual environment.
Install Poetry as per [docs](https://python-poetry.org/docs/#installation).
Use the following steps to set up Poetry shell.

```shell
# CWD = repository root
poetry install
poetry shell

# To exit the virtual environment
exit
```

After the virtual environment has been setup properly, then any errors which
you may have seen in previous attempts to build/test/install `hse` should be
resolved, at least partially.
