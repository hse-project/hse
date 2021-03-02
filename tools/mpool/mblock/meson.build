sources_mpio = files(
    'mpiotest.c',
)

sources_mpprof = files(
    'mpool_profile.c',
)

executable(
    'mpiotest',
    sources_mpio,
    c_args: common_tools_c_args,
    include_directories: common_tools_include_directories,
    dependencies: [
        common_tools_dependencies,
    ],
    install: get_option('install-tools'),
    install_rpath: exe_install_rpath,
)

executable(
    'mpool_profile',
    sources_mpprof,
    c_args: common_tools_c_args,
    include_directories: common_tools_include_directories,
    dependencies: [
        common_tools_dependencies,
    ],
    install: get_option('install-tools'),
    install_rpath: exe_install_rpath,
)
