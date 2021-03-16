hse_cli_sources = [
    files(
        'cli_util.c',
        'hse_cli.c',
    ),
    _config_h,
]

hse_cli_c_args = [
    '-DCOMPANE="CLI"',
]

hse_cli_dependencies = [
    hse_dep,
    hse_dependencies,
]

hse_cli_include_directories = [
    component_root_includes,
    third_party_includes,
    util_includes,
    get_option('mpool-include-dir'),
]

hse_cli = executable(
    meson.project_name() + hse_major_version,
    hse_cli_sources,
    c_args: hse_cli_c_args,
    include_directories: hse_cli_include_directories,
    dependencies: hse_cli_dependencies,
    install: true,
    install_rpath: exe_install_rpath,
    gnu_symbol_visibility: 'hidden',
)

meson.override_find_program('hse1', hse_cli)

executable_paths += meson.current_build_dir()
