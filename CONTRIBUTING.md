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
* All new code must include unit or functional tests.
* All existing unit and functional tests must pass.
* For any data path changes, run the benchmark suite before and after
your PR to verify there is no regression.

## Information on Contributing to this Repo

### Coding Style

Proper formatting is required for passing continuous integration checks.

#### C

HSE uses `clang-format` for formatting C code. We include a script at
[`scripts/dev/clang-format.sh`](./scripts/dev/clang-format.sh) that you can
use to format either the whole tree or certain files. The script can also be
used to check formatting. It is recommended that you just hook up your editor to
format files for you however.

### Documentation

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

### Testing

If you choose to add a feature or a bug fix to HSE, make sure to add any
necessary tests to confirm that the contribution works as it should. Please
refer to the directory structure underneath [`tests`](./tests) for where it
would be appropriate to add your tests.

Tests can be run using the following:

```shell
meson test -C build [tests...]
```

We recommend running tests through Meson always. There is a lot of
infrastructure setup through Meson that you would have to duplicate otherwise.

To list tests, run the following:

```shell
meson test -C build --list
```

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

#### Mocking

HSE uses a homegrown mocking framework at the moment. When unit testing, it may
be necessary to mock various components of HSE.

Relationship between mockable functions, mock groups, and source files:

* Mockable functions are organized into groups.
* Groups are implemented in `.c` source files and declared in `.h` header files.
* Each `.c` source file can implement multiple groups.
* Each `.h` header file declares at most one group.

##### Annotated Template

In this example:

* Source file `foo.c` implements groups `foo` and `foo_print`
* Header file `foo.h` decalares group `foo`
* Header file `foo_print.h` decalares group `foo_print`

By convention, the group is named after the header file that declares it.

###### `foo.h`

```c
/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright YYYY Micron Technology, Inc.
 */

#ifndef FOO_H
#define FOO_H

/* Declare that this file contains function protoypes for the "foo" mock group.
 */
/* MTF_MOCK_DECL(foo) */

/* Mark mockable functions with an MTF_MOCK comment, which must appear
 * immediately before the function definition.
 */
/* MTF_MOCK */
struct foo *foo_create(void);

/* MTF_MOCK */
void
foo_destroy(struct foo *foo);

/* This function is not mockable because there is no MTF_MOCK comment. */
void foo_bar(void);

/* Include generated file that defines macros that wrap mockable functions. */
#if HSE_MOCKING
#include "foo_ut.h"
#endif

#endif
```

###### `foo_print.h`

```c
/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright YYYY Micron Technology, Inc.
 */

#ifndef FOO_PRINT_H
#define FOO_PRINT_H

/* MTF_MOCK_DECL(foo_print) */

/* MTF_MOCK */
void foo_print(void);

#if HSE_MOCKING
#include "foo_print_ut.h"
#endif

#endif
```

###### `foo.c`

```c
/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright YYYY Micron Technology, Inc.
 */

/* Declare that this file implements functions in the `foo` and `foo_print`
 * groups. These are typically defined at the top of the file immediately after
 * the copyright notice.
 */
#define MTF_MOCK_IMPL_foo
#define MTF_MOCK_IMPL_foo_print

/* Header files containing prototypes of mockable functions MUST be included
 * after the MTF_MOCK_IMPL definitions.
 */
#include "abc.h"
#include "bar.h"
#include "foo.h"
#include "foo_print.h"
#include "xyz.h"

/* This function is mockable by virtue of the MTF_MOCK annotation in foo.h. No
 * annoation is needed here.
 */
struct foo *
foo_create()
{
    // ...
}

void foo_destroy(struct foo *foo)
{
    // ...
}

void foo_print(void)
{
    // ...
}

/* This function is not mockable since the prototype in foo.h is not annotated
 * with MTF_MOCK.
 */
void foo_bar(void)
{
    // ...
}

/* Must be at end of source file. Shoud have one include for each MTF_MOCK_IMPL
 * definition at the top of the source file. These generated files define hooks
 * to access the mocked and real versions of mockable functions.
 */
#if HSE_MOCKING
#include "foo_ut_impl.i"
#include "foo_print_ut_impl.i"
#endif
```

##### Troubleshooting

When implementing mocking, you may run into one of the following issues:

###### `mapi_idx_foo_create undeclared`

Build does not know that `foo.h` contains mock declarations.

Add `foo.h` to the list of mocked headers in
[`tests/mocks/meson.build`](./tests/mocks/meson.build).

###### `unknown type name mtfm_foo_create_fp`

Indicates the following code is missing from the bottom of `foo.h`:

```c
#ifdef HSE_MOCKING
#include "foo_ut.h"
#endif
```

###### `multiple definition of mtfm_foo_foo_create_getreal`

More than on source file has `#include "cn_foo_ut_impl.i"`.

###### `undefined reference to mtfm_foo_foo_create_get`

Could indicate one of two things:

* The source file with `foo_create()` is not compiled
* The source file with `foo_create()` is missing `#include "cn_foo_ut_impl.i"`

###### `in expansion of macro foo_create, expected identifier or '(' before '{' token`

Source file implemeting `foo_create()` is missing `#define MTF_MOCK_IMPL_foo`,
where `foo` is the mock group containing `foo_create()`.

### Sanitized Builds

Meson has built-in support for sanitized builds.

Run `meson configure` to see what options exist for `b_sanitize`. It is
important to reduce issues like memory leaks and undefined behavior when
developing HSE. Common sanitizers you may want to use during development are
`address` and `undefined`.

HSE maintainers aim to have all tests pass with
`-Db_sanitize=address,undefined`. Keeping that baseline is extremely important.
All contributions will be required to meet that same standard. Compiling with
these options locally can help contributors identify issues early on in their
work.

### Coverage

HSE uses `gcovr` to get code coverage. To enable coverage and get the coverage
reports run the following:

```shell
meson build --buildtype=debug -Db_coverage=true
meson compile -C build
meson test -C build --setup=ci
meson compile gcovr-{html,text,json,xml} -C build
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
