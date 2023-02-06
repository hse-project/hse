# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# SPDX-FileCopyrightText: Copyright 2021 Micron Technology, Inc.

project(
    'rbtree',
    ['c'],
    license: 'BSD-2-Clause'
)

libbsd_dep = dependency('libbsd')

rbtree = library(
    meson.project_name(),
    ['rbtree.c'],
    dependencies: [
        libbsd_dep,
    ],
    gnu_symbol_visibility: 'hidden',
)

rbtree_dep = declare_dependency(
    link_with: rbtree,
    dependencies: [
        libbsd_dep,
    ],
    include_directories: '.'
)
