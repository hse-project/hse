tests = {
    'kvdb_limits_test': {
        'type': 'utest',
    },
    'max_key_cnt_test': {
        'type': 'shell',
        'suites': ['long'],
        'timeout': 60000,
    },
}

foreach t, params : tests
    t_type = params.get('type', 0)

    if t_type == 'shell'
        # Make sure every file is executable
        run_command(
            sh,
            '-c',
            '[ -x "@0@" ]'.format(meson.current_source_dir() / t + '.sh'),
            check: true
        )

        t_exe = bash
        t_depends = [ hse_cli_symlink ]
        t_workdir = fs.parent(meson.current_source_dir())
        t_env = environment({
            'HSE_TEST_RUNNER_RUNNER': 'bash',
        })
        t_args = [
            meson.current_source_dir() / '@0@.sh'.format(t),
        ]

    elif t_type == 'utest'
        t_exe = executable(
            t,
            '@0@.c'.format(t),
            params.get('sources', []),
            c_args: params.get('c_args', []),
            include_directories: [
                hse_include_directories,
                tools_includes,
                params.get('include_directories', []),
            ],
            dependencies: [
                hse_internal_dep,
                hse_dependencies,
                hse_fixtures_dep,
                hse_test_framework_dep,
                params.get('dependencies', [])
            ],
        )

        t_depends = []
        t_workdir = meson.current_source_dir()
        t_env = environment()
        t_args = []
    else
        continue

    endif

    test(
        t,
        t_exe,
        args: t_args,
        workdir: t_workdir,
        depends: t_depends,
        env: t_env,
        suite: ['functional', 'limits'] + params.get('suites', []),
        timeout: params.get('timeout', 300),
    )
endforeach
