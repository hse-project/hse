subdir('include')
subdir('lib')

libhse_error = static_library(
    'hse-error',
    error_sources,
    include_directories: [
        component_root_includes,
        error_includes,
        public_includes,
        util_includes,
    ],
    dependencies: [
        libbsd_dep,
    ],
    gnu_symbol_visibility: 'hidden'
)

libhse_error_dep = declare_dependency(
    link_with: libhse_error,
    include_directories: [
        error_includes,
        public_includes,
        # TODO: Remove when compiler.h moves around
        util_includes,
    ]
)
