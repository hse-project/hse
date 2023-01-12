subdir('include')
subdir('lib')

hse_logging = static_library(
    '@0@-logging'.format(meson.project_name()),
    logging_sources,
    c_args: cc_supported_arguments,
    include_directories: [
        logging_includes,
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
        logging_includes,
    ],
    dependencies: [
        hse_error_dep,
    ]
)
