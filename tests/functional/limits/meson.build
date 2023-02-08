# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# SPDX-FileCopyrightText: Copyright 2022 Micron Technology, Inc.

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
    t_type = params.get('type')

    if t_type == 'shell'
        # Make sure every file is executable
        run_command(
            sh,
            '-c',
            '[ -x "@0@" ]'.format(meson.current_source_dir() / t + '.sh'),
            check: true
        )

        t_exe = bash
        t_depends = [hse_exe_symlink]
        t_workdir = fs.parent(meson.current_source_dir())
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
                hse_test_fixtures_dep,
                hse_test_framework_dep,
                params.get('dependencies', [])
            ],
        )

        t_depends = []
        t_workdir = meson.current_source_dir()
        t_args = []
    else
        error('Unknown test type')
    endif

    test(
        t,
        t_exe,
        args: t_args,
        workdir: t_workdir,
        depends: t_depends,
        suite: ['functional', 'limits'] + params.get('suites', []),
        timeout: params.get('timeout', 300),
    )
endforeach
