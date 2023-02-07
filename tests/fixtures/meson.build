# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# SPDX-FileCopyrightText: Copyright 2021 Micron Technology, Inc.

subdir('include')
subdir('lib')

hse_test_fixtures = static_library(
    '@0@-test-fixtures'.format(meson.project_name()),
    test_fixtures_sources,
    c_args: cc_supported_arguments,
    include_directories: test_fixtures_includes,
    dependencies: hse_internal_dep,
    gnu_symbol_visibility: 'hidden'
)

hse_test_fixtures_dep = declare_dependency(
    link_with: hse_test_fixtures,
    include_directories: [
        test_fixtures_includes,
    ],
    dependencies: [
        hse_error_dep,
        hse_internal_dep,
    ]
)
