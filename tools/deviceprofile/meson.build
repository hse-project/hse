sources = files(
    'deviceprofile_app.c',
    'deviceprofile.c',
)

c_args = [
    common_tools_c_args,
    '-DHDR_HISTOGRAM_C_FROM_SUBPROJECT=@0@'.format(HdrHistogram_c_from_subproject ? 1 : 0),
]

executable(
    'deviceprofile',
    sources,
    c_args: c_args,
    include_directories: common_tools_include_directories,
    dependencies: [
        common_tools_dependencies,
        HdrHistogram_c_dep,
    ],
    install: get_option('install-tools'),
    install_rpath: exe_install_rpath,
)
