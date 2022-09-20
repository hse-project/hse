subdir('include')
subdir('lib')

hse_logging = static_library(
    '@0@-logging'.format(meson.project_name()),
    hse_logging_sources,
    build_config_h,
    include_directories: [
        hse_logging_includes,
        component_root_includes,
        util_includes,
    ],
    dependencies: [
        hse_error_dep,
        rbtree_dep,
    ],
    gnu_symbol_visibility: 'hidden'
)

hse_logging_dep = declare_dependency(
    link_with: hse_logging,
    include_directories: hse_logging_includes,
    dependencies: [hse_error_dep]
)
