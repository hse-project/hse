# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# SPDX-FileCopyrightText: Copyright 2022 Micron Technology, Inc.

if not meson.is_cross_build() and getconf.found()
    page_size = run_command(getconf, 'PAGE_SIZE', check: true).stdout().strip().to_int()
else
    page_size = meson.get_external_property('page-size', native: not meson.is_cross_build())
endif

if page_size != 4096
    error('A page size other than 4096 is unsupported')
endif

configure_file(
    input: 'page.h.in',
    output: 'page.h',
    configuration: configuration_data({
        'PAGE_SIZE': page_size,
    })
)
