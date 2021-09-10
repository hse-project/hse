project(
    'crc32c',
    ['c']
)

crc32c = library(
    meson.project_name(),
    ['crc32c.c'],
    gnu_symbol_visibility: 'hidden'
)

crc32c_dep = declare_dependency(
    link_with: crc32c,
    include_directories: '.'
)
