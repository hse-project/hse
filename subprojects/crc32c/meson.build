# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# SPDX-FileCopyrightText: Copyright 2021 Micron Technology, Inc.

project(
    'crc32c',
    'c'
)

crc32c = library(
    meson.project_name(),
    'crc32c.c',
    gnu_symbol_visibility: 'hidden',
    override_options: [
        # Inline assembly functions cannot be properly LTOed. One workaround
        # would be to always call crc32c_sw(), but then you would lose out in
        # the case when LTO is disabled. Another solution would be to mark
        # assembly function as noinline, but since these files come from
        # elsewhere, it is probably best to not edit them. For these reasons,
        # always forcibly disable LTO.
        'b_lto=false',
    ]
)

crc32c_dep = declare_dependency(
    link_with: crc32c,
    include_directories: '.'
)
