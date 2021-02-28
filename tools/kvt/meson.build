sources = files(
    'kvt.c',
)

executable(
    'kvt',
    sources + tools_third_party_sources,
    c_args: common_tools_c_args,
    include_directories: [
        common_tools_include_directories,
        tools_third_party_includes,
    ],
    dependencies: [
        common_tools_dependencies,
        ncurses_dep,
    ],
    install: get_option('install-tools'),
    install_rpath: exe_install_rpath,
)
