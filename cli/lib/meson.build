if not get_option('cli') and get_option('tools').disabled() and not get_option('tests')
    libhse_cli_dep = disabler()
    subdir_done()
endif

libcurl_dep = dependency(
    'libcurl',
    version: '>=7.58.0',
    fallback: 'curl',
    default_options: [
        'default_library=static',
        'warning_level=0',
        'werror=false',
    ],
    required: get_option('cli') or get_option('tools').enabled() or get_option('tests'),
    disabler: true
)

libhse_cli_sources = files(
    'param.c',
    'program.c',
    'rest/api.c',
    'rest/buffer.c',
    'rest/client.c',
    'tprint.c'
)

libhse_cli = static_library(
    'hse-cli',
    libhse_cli_sources,
    c_args: cc.get_supported_arguments('-Wconversion'),
    include_directories: [
        cli_includes,
        component_root_includes,
        rest_includes,
        # Remove util_includes when compiler.h moves around
        util_includes,
    ],
    dependencies: [
        cjson_dep,
        hse_error_dep,
        libcurl_dep,
        rbtree_dep,
    ],
    gnu_symbol_visibility: 'hidden'
)

libhse_cli_dep = declare_dependency(
    link_with: libhse_cli,
    include_directories: [
        cli_includes,
        # Exposes merr_t in a public header
        component_root_includes,
    ],
    dependencies: [
        libcurl_dep,
    ]
)
