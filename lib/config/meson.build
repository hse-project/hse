subdir('include')
subdir('lib')

hse_config = static_library(
    '@0@-config'.format(meson.project_name()),
    config_sources,
    c_args: cc.get_supported_arguments('-Wconversion'),
    include_directories: [
        component_root_includes,
        config_includes,
        util_includes,
    ],
    dependencies: [
        cjson_dep,
        hse_error_dep,
        hse_logging_dep,
        libbsd_dep,
    ],
    gnu_symbol_visibility: 'hidden'
)

hse_config_dep = declare_dependency(
    link_with: hse_config,
    include_directories: [
        # Exposes merr_t in a public header
        component_root_includes,
        config_includes,
        # TODO: Remove when compiler.h moves around
        util_includes,
    ],
    dependencies: [
        cjson_dep,
        hse_error_dep,
    ]
)
