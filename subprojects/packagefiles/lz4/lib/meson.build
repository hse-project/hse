# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# SPDX-FileCopyrightText: Copyright 2020 Micron Technology, Inc.

c_args = []

if get_option('default_library') == 'static'
    # important definition, without this calls to lz4 won't be inlined
    c_args += '-DLZ4LIB_VISIBILITY=__attribute__((visibility("hidden")))'
endif

liblz4 = library(
    'lz4',
    ['lz4.c'],
    c_args: c_args,
    version: meson.project_version(),
    gnu_symbol_visibility: 'hidden'
)

liblz4_dep = declare_dependency(
    link_with: liblz4,
    version: meson.project_version(),
    include_directories: [
        include_directories('.'),
    ]
)
