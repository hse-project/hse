# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# SPDX-FileCopyrightText: Copyright 2021 Micron Technology, Inc.

tests = {
    'test_kmt_ro': {
        'suite': 'kmt',
        'timeout': 600,
        'depends': [
            tool_targets['kmt'],
        ],
    },
    'test_kmt_rw': {
        'suite': 'kmt',
        'timeout': 600,
        'depends': [
            tool_targets['kmt'],
        ],
    },
    'test_ycsb_2tb_putget': {
        'suite': 'ycsb',
        'timeout': 0,
        'depends': [
            hse_exe,
            hse_java_depends,
        ],
    },
    'test_ycsb_2tb_scan': {
        'suite': 'ycsb',
        'timeout': 0,
        'depends': [
            hse_exe,
            hse_java_depends,
        ],
        'env': environment({
            'LD_LIBRARY_PATH': hse_java.found() ? fs.parent(hsejni.full_path()) : '',
        }),
    }
}

foreach t, params : tests
    path = meson.current_source_dir() / '@0@.py'.format(t)
    testname = fs.stem(path)

    benchmark(
        testname,
        python,
        args: [
            path,
        ],
        depends: [hse_python_depends, params.get('depends', [])],
        suite: params.get('suite', ''),
        timeout: params.get('timeout', 60),
        env: params.get('env', run_env),
    )
endforeach
