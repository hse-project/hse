# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# SPDX-FileCopyrightText: Copyright 2021 Micron Technology, Inc.

subdir('include')
subdir('lib')

hse_pidfile = static_library(
    '@0@-pidfile'.format(meson.project_name()),
    pidfile_sources,
    c_args: cc_supported_arguments,
    include_directories: [
        pidfile_includes,
    ],
    dependencies: [
        cjson_dep,
        libbsd_dep,
        hse_error_dep,
    ],
    gnu_symbol_visibility: 'hidden'
)

hse_pidfile_dep = declare_dependency(
    link_with: hse_pidfile,
    include_directories: [
        pidfile_includes,
    ],
    dependencies: [
        hse_error_dep,
    ]
)
