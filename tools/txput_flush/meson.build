sources = files(
    'txput_flush.c',
    '..' / 'common.c',
    '..' / 'kvs_helper.c',
)

executable(
    'txput_flush',
    sources,
    c_args: common_tools_c_args,
    include_directories: [
        common_tools_include_directories,
        '..',
    ],
    dependencies: [
        common_tools_dependencies,
    ],
    install: get_option('install-tools'),
    install_rpath: exe_install_rpath,
)
