# Using clang-format in HSE

The configuration file for
[clang-format](https://clang.llvm.org/docs/ClangFormat.html) is named
`.clang-format` at the top the source tree.  It was originally written to work
with clang-format version 13 and should be supported by more recent versions of
clang-format.

Configuration file documentation for version 13 can be found
(here)[https://releases.llvm.org/13.0.0/tools/clang/docs/ClangFormatStyleOptions.html].
The latest version documented
(here)[https://clang.llvm.org/docs/ClangFormat.html].

## Using clang-format

To use clang-format with HSE, your current working directory must be in the HSE source tree
so that that clang-format can find the configuration file.

To format a single file:
```
clang-format -style=file -i -fallback-style=none '<file>'
```

To format all source files:
```
git ls-file lib tests tools | grep '\.[ch]$' | \
    xargs clang-format -style=file -i -fallback-style=none
```

## Working around clang-format

### Disable a region of code

Clang-format understands also special comments that switch formatting in a
delimited range. The code between
a comment `// clang-format off` or `/* clang-format off */` up to
a comment `// clang-format on` or `/* clang-format on */` will not be formatted.
The comments themselves will be formatted (aligned) normally.

### Use trailing commas in array initializers to force one entry per line

This behavior is documented in the description of configuration parameter
[InsertTrailingCommas](https://clang.llvm.org/docs/ClangFormatStyleOptions.html#inserttrailingcommas).


Without trailing comma:
```
int table[] = { 1 * 1000 * 1000, 2 * 1000 * 1000, 3 * 1000 * 1000, 4 * 1000 * 1000,
    5 * 1000 * 1000, 6 * 1000 * 1000, 7 * 1000 * 1000 };
```

With trailing comma:
```
int table[] = {
    1 * 1000 * 1000,
    2 * 1000 * 1000,
    3 * 1000 * 1000,
    4 * 1000 * 1000,
    5 * 1000 * 1000,
    6 * 1000 * 1000,
    7 * 1000 * 1000,
};
```

### Prevent deleting newlines with an end-of-line C++ comment


## Notes and TODO Items

### Eliminate attribute macros with parameters where possible

Use of `__aligned(64)` can result in this format:
```
const u_char u64tostrtab[] __aligned(
    64) = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
```

A workaround:
```
#define HSE_ALIGNED_64 __aligned(64)

const u_char u64tostrtab[] HSE_ALIGNED_64 =
    "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
```
