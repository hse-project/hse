# Unit Test Mocking

Relationship between mockable functions, mock groups, and source files:
- Mockable functions are organized into groups.
- Groups are implemented in `.c` source files and declared in `.h` header files.
- Each `.c` source file can implement multiple groups.
- Each `.h` header file declares at most one group.

Limitations:
- Inline functions cannot be mocked.

## Annotated Templates

In this example:
- Source file `foo.c` implements groups `foo` and `foo_print`
- Header file `foo.h` decalares group `foo`
- Header file `foo_print.h` decalares group `foo_print`

By convention, the group is named after the header file that declares it.

### File `foo.c`

```
/*
 * Copyright (C) 2022 Micron Technology, Inc.  All rights reserved.
 */

#define MTF_MOCK_IMPL_foo              <-- Declare that this file implements functions
#define MTF_MOCK_IMPL_foo_print            in the `foo` and `foo_print` groups.  These
                                           are typically defined at the top of the
                                           file immediately after the copyright notice.
...

#include "bar.h
#include "abc.h
#include "foo.h"                        <-- Header files containing prototypes of
#include "foo_print.h"                      mockable functions MUST be included
#include "xyz.h                             after the MTF_MOCK_IMPL definitions.


...

struct foo *foo_create()                <-- This function is mockable by virtue the
{                                           MTF_MOCK annotation in foo.h.  No annoation
    ...                                     is needed here.
}

void foo_destroy(struct foo *foo)
{
    ...
}

void foo_print(void)
{
    ...
}

void foo_bar(void)                      <-- This function is not mockable since the
{                                           prototype in foo.h is not annotated with
    ...                                     MTF_MOCK.
}


#if HSE_MOCKING                         <-- Must be at end of source file. Shoud have one
#include "foo_ut_impl.i"                    include for each MTF_MOCK_IMPL definition at
#include "foo_print_ut_impl.i"              the top of the source file.  These generated
#endif                                      files define hooks to access the mocked and
                                            real versions of mockable functions.
```

### File `foo.h`
```
/*
 * Copyright (C) 2022 Micron Technology, Inc.  All rights reserved.
 */

#ifndef FOO_H
#define FOO_H

#include <...>

/* MTF_MOCK_DECL(foo) */                <-- Declare that this file contains function
                                            protoypes for the "foo" mock group.

/**
 * Create a foo object.
 */
/* MTF_MOCK */                          <-- Mark mockable functions with an MTF_MOCK
struct foo *foo_create(void);               comment, which must appear immediately
                                            before the function definition.

/* MTF_MOCK */
void
foo_destroy(struct foo *foo);

void foo_bar(void);                     <-- This function is not mockable because
                                            there is no MTF_MOCK comment.

#if HSE_MOCKING                         <-- Include generated file that defines macros
#include "foo_ut.h"                         that wrap mockable functions.
#endif

#endif
```

### File `foo_print.h`
```
/*
 * Copyright (C) 2022 Micron Technology, Inc.  All rights reserved.
 */

#ifndef FOO_PRINT_H
#define FOO_PRINT_H

#include <...>

/* MTF_MOCK_DECL(foo_print) */

/* MTF_MOCK */
void foo_print(void);

#if HSE_MOCKING
#include "foo_print_ut.h"
#endif

#endif
```
## Troubleshooting Build Problems

First things to check:
- Ensure include files marked with MTF_MOCK markers are mentioned in `tests/mocks/meson.build`.
- Reboot your build: remove the build dir and re-run `meson setup`

### Compilation error messages and their causes

#### `foo_ut.h:135:49: error: mapi_idx_foo_create undeclared`

Likely problem:
- Build does not know that `foo.h` contains mock declarations.  Fix: Add
  `foo.h` to the list of mocked headers in `tests/mocks/meson.build`.

#### `unknown type name mtfm_foo_create_fp`

Full error message:
```
In file included XYZ.c:88:
    tests/mocks/foo_ut_impl.i:13:1: error: unknown type name mtfm_foo_create_fp
```

This error indicates the following code is missing from the bottom of `foo.h`:
```
#ifdef HSE_MOCKING
#include "foo_ut.h"
#endif
```

#### `cn_foo_ut_impl.i:21: multiple definition of mtfm_foo_foo_create_getreal`

Likely problems:
- More than on source file has `#include "cn_foo_ut_impl.i"`

#### `in function XYZ: undefined reference to mtfm_foo_foo_create_get`

This error shows up in function `XYZ()` because `XYZ()` is calling `foo_create()`.

Likely problems:
- the source file with `foo_create()` is not compiled.
- the source file with `foo_create()` is missing `#include "cn_foo_ut_impl.i"`.

#### `in expansion of macro foo_create, expected identifier or '(' before '{' token`

Full error message:
```
In file included from foo.h:42,
                 from foo.c:12:
tests/mocks/foo_ut.h:19:2: error: expected identifier or ( before { token
   19 | ({ \
      |  ^
foo.c:42:1: note: in expansion of macro foo_create
   42 | foo_create(
      | ^~~~~~~
```

Likely problems:
- Source file implemeting `foo_create()` is missing `#define MTF_MOCK_IMPL_foo`, where `foo`
  is the mock group containing `foo_create()`.
