cli_sources = [
    files(
        'param.c',
    ),
]

if get_option('cli') or get_option('tools')
    libhse_cli = static_library(
        'hse-cli',
        cli_sources,
        include_directories: [
            cli_includes,
            component_root_includes,
        ],
        gnu_symbol_visibility: 'hidden',
    )

    libhse_cli_dep = declare_dependency(
        link_with: libhse_cli,
        include_directories: [
            cli_includes,
        ],
    )
else
    libhse_cli_dep = disabler()
endif
