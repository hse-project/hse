rbtree = static_library(
    'rbtree',
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
)
