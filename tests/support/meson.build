# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# SPDX-FileCopyrightText: Copyright 2020 Micron Technology, Inc.

subdir('include')
subdir('lib')

hse_test_support = static_library(
    '@0@-test-support'.format(meson.project_name()),
    test_support_sources,
    include_directories: [
        test_support_includes,
    ],
    dependencies: [
        hse_error_dep,
        rbtree_dep,
        xoroshiro_dep,
    ],
    gnu_symbol_visibility: 'hidden'
)

hse_test_support_dep = declare_dependency(
    link_with: hse_test_support,
    include_directories: [
        test_support_includes,
    ],
    dependencies: [
        hse_error_dep,
    ]
)
