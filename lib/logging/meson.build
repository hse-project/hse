subdir('include')
subdir('lib')

hse_logging = static_library(
    '@0@-logging'.format(meson.project_name()),
    hse_logging_sources,
    include_directories: [
        hse_logging_includes,
        component_root_includes,
        util_includes,
    ],
    dependencies: [
        hse_error_dep,
    ],
    gnu_symbol_visibility: 'hidden'
)

hse_logging_dep = declare_dependency(
    link_with: hse_logging,
    include_directories: [
        # Exposes merr_t in a public header
        component_root_includes,
        hse_logging_includes,
    ],
    dependencies: [hse_error_dep]
)
