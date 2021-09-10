The HSE code is generally licensed under the "Apache 2.0" license with two
exceptions. See hse/docs/SourceConventions.md for how this is to be indicated
within the HSE source files themselves.

# Exceptions

The following directories contain code not written by HSE contributors, but used
by HSE:

* subprojects/crc32c
* subprojects/hyperloglog
* subprojects/rbtree
* subprojects/xoroshiro

Such code continues to be licensed under its original terms, but may exist
within the HSE tree with changes (typically small).
