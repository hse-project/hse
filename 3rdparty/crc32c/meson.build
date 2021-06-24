crc32c = static_library(
    'crc32c',
    ['crc32c.c'],
    gnu_symbol_visibility: 'hidden',
)

crc32c_dep = declare_dependency(
    link_with: crc32c,
)
