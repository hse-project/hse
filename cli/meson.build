subdir('include')
subdir('lib')

if not get_option('cli')
    subdir_done()
endif

cli_name = meson.project_name() + hse_major_version

hse_cli_sources = [
    files(
        'cli_util.c',
        'hse_cli.c',
    ),
    _config_h,
]

hse_cli_c_args = [
    '-DCOMPANE="CLI"',
    '-DHSE_EXPERIMENTAL',
]

hse_cli_dependencies = [
    hse_dep,
    libhse_cli_dep,
    hse_dependencies,
]

hse_cli_include_directories = [
    component_root_includes,
    third_party_includes,
    util_includes,
]

hse_cli = executable(
    cli_name,
    hse_cli_sources,
    c_args: hse_cli_c_args,
    include_directories: hse_cli_include_directories,
    dependencies: hse_cli_dependencies,
    install: true,
    install_rpath: exe_install_rpath,
    gnu_symbol_visibility: 'hidden',
)

custom_target(
    'cli-symlink',
    build_by_default: true,
    input: hse_cli,
    command: [
        'ln',
        '--force',
        '--symbolic',
        meson.project_build_root() / '@INPUT@',
        meson.project_build_root() / '@OUTPUT@',
    ],
    output: meson.project_name(),
)

meson.override_find_program(cli_name, hse_cli)

executable_paths += meson.current_build_dir()

meson.add_install_script(
    meson.project_source_root() / 'scripts/meson-hooks/install/cli-symlink.sh',
    get_option('bindir'),
    fs.name(hse_cli.full_path()),
    meson.project_name(),
)
