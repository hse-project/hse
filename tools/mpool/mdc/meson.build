sources_mdctest = files(
    'mdctest.c',
)

sources_mdcperf = files(
    'common.c',
    'thread.c',
    'mdcperf.c',
)

sources_mdctool = files(
    'mdc_tool.c',
)

executable(
    'mdctest',
    sources_mdctest,
    c_args: common_tools_c_args,
    include_directories: common_tools_include_directories,
    dependencies: [
        common_tools_dependencies,
    ],
    install: get_option('install-tools'),
    install_rpath: exe_install_rpath,
)

executable(
    'mdcperf',
    sources_mdcperf,
    c_args: common_tools_c_args,
    include_directories: common_tools_include_directories,
    dependencies: [
        common_tools_dependencies,
    ],
    install: get_option('install-tools'),
    install_rpath: exe_install_rpath,
)

executable(
    'mdc_tool',
    sources_mdctool,
    c_args: common_tools_c_args,
    include_directories: common_tools_include_directories,
    dependencies: [
        common_tools_dependencies,
    ],
    install: get_option('install-tools'),
    install_rpath: exe_install_rpath,
)
