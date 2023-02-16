# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# SPDX-FileCopyrightText: Copyright 2020 Micron Technology, Inc.

if not get_option('cli') and get_option('tools').disabled() and not get_option('tests')
    hse_cli_dep = disabler()
    hse_exe = disabler()
    hse_exe_symlink = disabler()
    subdir_done()
endif

subdir('include')
subdir('lib')

hse_cli = static_library(
    '@0@-cli'.format(meson.project_name()),
    cli_sources,
    c_args: cc_supported_arguments,
    include_directories: [
        cli_includes,
        rest_includes,
        # Remove util_includes when compiler.h moves around
        util_includes,
    ],
    dependencies: [
        cjson_dep,
        # TODO: Remove when the cli can depend on libhse-util
        hse_internal_dep,
        hse_error_dep,
        libcurl_dep,
        rbtree_dep,
    ],
    gnu_symbol_visibility: 'hidden'
)

hse_cli_dep = declare_dependency(
    link_with: hse_cli,
    include_directories: [
        cli_includes,
    ],
    dependencies: [
        hse_error_dep,
        libcurl_dep,
    ]
)

if not get_option('cli')
    hse_exe = disabler()
    hse_exe_symlink = disabler()
    subdir_done()
endif

exe_name = meson.project_name() + hse_major_version

exe_sources = files(
    'cli_util.c',
    'hse_cli.c',
    'storage_info.c',
    'storage_profile.c'
)

hse_exe = executable(
    exe_name,
    exe_sources,
    c_args: cc_supported_arguments,
    include_directories: [
        util_includes,
    ],
    dependencies: [
        cjson_dep,
        hse_dep,
        hse_cli_dep,
        hse_pidfile_dep,
        hse_logging_dep,
        libbsd_dep,
        threads_dep,
    ],
    install: true,
    install_rpath: rpath,
    gnu_symbol_visibility: 'hidden',
)

hse_exe_symlink = custom_target(
    'hse',
    build_by_default: true,
    input: hse_exe,
    command: [
        'ln',
        '--force',
        '--symbolic',
        fs.name(hse_exe.full_path()),
        '@OUTPUT@',
    ],
    output: meson.project_name(),
)

install_symlink(
    meson.project_name(),
    pointing_to: exe_name,
    install_dir: get_option('bindir')
)

meson.override_find_program(exe_name, hse_exe)

executable_paths += meson.current_build_dir()
