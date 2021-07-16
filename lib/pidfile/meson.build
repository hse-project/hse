subdir('include')
subdir('lib')

libhse_pidfile = static_library(
    'hse-pidfile',
    pidfile_sources,
    include_directories: [
        pidfile_includes,
        component_root_includes,
    ],
    dependencies: [
        cjson_dep,
        libbsd_dep,
    ],
    gnu_symbol_visibility: 'hidden',
)

libhse_pidfile_dep = declare_dependency(
    link_with: libhse_pidfile,
    include_directories: [
        pidfile_includes,
    ],
)
