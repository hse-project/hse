lz4 = library(
    'lz4',
    ['lz4.c'],
    c_args: [
        # important definition, without this calls to lz4 won't be inlined
        '-DLZ4LIB_VISIBILITY=__attribute__((visibility("hidden")))',
    ],
    version: meson.project_version(),
)

lz4_dep = declare_dependency(
    link_with: lz4,
    version: meson.project_version(),
    include_directories: [
        include_directories('.'),
    ],
)
