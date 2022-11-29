subdir('include')
subdir('lib')

hse_pidfile = static_library(
    '@0@-pidfile'.format(meson.project_name()),
    pidfile_sources,
    include_directories: [
        pidfile_includes,
        component_root_includes,
    ],
    dependencies: [
        cjson_dep,
        libbsd_dep,
        hse_error_dep,
    ],
    gnu_symbol_visibility: 'hidden'
)

hse_pidfile_dep = declare_dependency(
    link_with: hse_pidfile,
    include_directories: [
        # Exposes merr_t in a public header
        component_root_includes,
        pidfile_includes,
    ]
)
