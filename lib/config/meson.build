subdir('include')
subdir('lib')

hse_config = static_library(
    '@0@-config'.format(meson.project_name()),
    config_sources,
    c_args: cc_supported_arguments,
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
        config_includes,
        # TODO: Remove when compiler.h moves around
        util_includes,
    ],
    dependencies: [
        cjson_dep,
        hse_error_dep,
    ]
)
