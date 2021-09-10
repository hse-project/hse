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
