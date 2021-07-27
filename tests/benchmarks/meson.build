if not get_option('tools')
    warning('benchmarks have been disabled because tools are disabled')
    subdir_done()
elif not get_option('cli')
    warning('benchmarks have been disabled because the CLI is disabled')
    subdir_done()
endif

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
            hse_cli,
        ],
    },
    'test_ycsb_2tb_scan': {
        'suite': 'ycsb',
        'timeout': 0,
        'depends': [
            hse_cli,
        ],
    },
    'test_dbbench': {
        'suite': 'dbbench',
        'timeout': 0,
    },
}

# benchmarks may consume a great deal of space, so confine them to reuse a single home dir
home_dir = tests_dir / 'benchmark'

if not fs.exists(home_dir)
    run_command(
        'mkdir',
        home_dir,
        check: true,
    )
endif

foreach t, params : tests
    path = meson.current_source_dir() / t + '.py'
    testname = fs.stem(path)

    benchmark(
        testname,
        python,
        args: [
            path,
            '--home',
            home_dir,
        ],
        env: run_env,
        depends: [hse_python_depends, params.get('depends', [])],
        suite: params.get('suite', ''),
        timeout: params.get('timeout', 60),
    )
endforeach
