c_args = []

if get_option('default_library') == 'static'
    # important definition, without this calls to lz4 won't be inlined
    c_args += '-DLZ4LIB_VISIBILITY=__attribute__((visibility("hidden")))'
endif

lz4 = library(
    'lz4',
    ['lz4.c'],
    c_args: c_args,
    version: meson.project_version(),
)

lz4_dep = declare_dependency(
    link_with: lz4,
    version: meson.project_version(),
    include_directories: [
        include_directories('.'),
    ],
)
