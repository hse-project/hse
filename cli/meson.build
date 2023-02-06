# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# SPDX-FileCopyrightText: Copyright 2020 Micron Technology, Inc.

subdir('include')
subdir('lib')

if not get_option('cli')
    hse_cli = disabler()
    hse_cli_symlink = disabler()
    subdir_done()
endif

cli_name = meson.project_name() + hse_major_version

hse_cli_sources = files(
    'cli_util.c',
    'hse_cli.c',
    'storage_info.c',
    'storage_profile.c',
)

hse_cli_dependencies = [
    hse_dep,
    libhse_cli_dep,
    hse_dependencies,
]

hse_cli_include_directories = [
    component_root_includes,
    util_includes,
]

hse_cli = executable(
    cli_name,
    hse_cli_sources,
    c_args: cc_supported_arguments,
    include_directories: hse_cli_include_directories,
    dependencies: hse_cli_dependencies,
    install: true,
    install_rpath: rpath,
    gnu_symbol_visibility: 'hidden',
)

hse_cli_symlink = custom_target(
    'cli-symlink',
    build_by_default: true,
    input: hse_cli,
    command: [
        'ln',
        '--force',
        '--symbolic',
        fs.name(hse_cli.full_path()),
        '@OUTPUT@',
    ],
    output: meson.project_name(),
)

install_symlink(
    meson.project_name(),
    pointing_to: cli_name,
    install_dir: get_option('bindir')
)

meson.override_find_program(cli_name, hse_cli)

executable_paths += meson.current_build_dir()
