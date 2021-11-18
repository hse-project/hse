tests = {
    'test_kmt_ro': {
        'suite': 'kmt',
        'timeout': 600,
        'depends': [
            tool_targets['kmt'],
        ],
        'env': environment({
            'HSE_TEST_RUNNER_RUNNER': 'python',
        })
    },
    'test_kmt_rw': {
        'suite': 'kmt',
        'timeout': 600,
        'depends': [
            tool_targets['kmt'],
        ],
        'env': environment({
            'HSE_TEST_RUNNER_RUNNER': 'python',
        })
    },
    'test_ycsb_2tb_putget': {
        'suite': 'ycsb',
        'timeout': 0,
        'depends': [
            hse_cli,
        ],
        'env': environment({
            'HSE_TEST_RUNNER_RUNNER': 'python',
            'LD_LIBRARY_PATH': meson.project_build_root() / 'hsejni' / 'src',
        })
    },
    'test_ycsb_2tb_scan': {
        'suite': 'ycsb',
        'timeout': 0,
        'depends': [
            hse_cli,
        ],
        'env': environment({
            'HSE_TEST_RUNNER_RUNNER': 'python',
            'LD_LIBRARY_PATH': meson.project_build_root() / 'hsejni' / 'src',
        })
    },
    'test_dbbench': {
        'suite': 'dbbench',
        'timeout': 0,
        'depends': [
            db_bench,
        ],
        'env': environment({
            'HSE_TEST_RUNNER_RUNNER': 'python',
        })
    },
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
