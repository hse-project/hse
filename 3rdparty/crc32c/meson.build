crc32c = static_library(
    'crc32c',
    ['crc32c.c'],
    c_args: [
        '-fvisibility=hidden',
    ],
)

crc32c_dep = declare_dependency(
    link_with: crc32c,
)
