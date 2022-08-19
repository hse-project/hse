subdir('include')
subdir('lib')

hse_error = static_library(
    '@0@-error'.format(meson.project_name()),
    hse_error_sources,
    include_directories: [
        component_root_includes,
        hse_error_includes,
        public_includes,
        util_includes,
    ],
    dependencies: [
        libbsd_dep,
    ],
    gnu_symbol_visibility: 'hidden'
)

hse_error_dep = declare_dependency(
    link_with: hse_error,
    include_directories: [
        hse_error_includes,
        public_includes,
        # TODO: Remove when compiler.h moves around
        util_includes,
    ]
)
