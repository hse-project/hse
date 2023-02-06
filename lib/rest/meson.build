# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# SPDX-FileCopyrightText: Copyright 2022 Micron Technology, Inc.

subdir('include')
subdir('lib')

hse_rest = static_library(
    '@0@-rest'.format(meson.project_name()),
    rest_sources,
    c_args: cc_supported_arguments,
    include_directories: [
        component_root_includes,
        public_includes,
        rest_includes,
        util_includes,
    ],
    dependencies: [
        # Required because of cJSON.h being exposed in hse_util/data_tree.h...ugh
        cjson_dep,
        hse_error_dep,
        hse_logging_dep,
        libbsd_dep,
        libevent_dep,
        libevent_pthreads_dep,
        rbtree_dep,
    ],
    gnu_symbol_visibility: 'hidden'
)

hse_rest_dep = declare_dependency(
    link_with: hse_rest,
    include_directories: [
        rest_includes,
    ],
    dependencies: [
        hse_error_dep,
    ]
)
