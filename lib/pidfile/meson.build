subdir('include')
subdir('lib')

hse_pidfile = static_library(
    'hse-pidfile',
    hse_pidfile_sources,
    include_directories: [
        hse_pidfile_includes,
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
    include_directories: hse_pidfile_includes
)
