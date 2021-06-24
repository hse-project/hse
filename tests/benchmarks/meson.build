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
        'depends': [
            tool_targets['kmt'],
        ],
    },
    'test_kmt_rw': {
        'suite': 'kmt',
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
    'test_dbbench.py': {
        'suite': 'dbbench',
        'timeout': 0,
    },
}

foreach t, params : tests
    home_dir = tests_dir / t
    if not fs.exists(home_dir)
        run_command(
            'mkdir',
            home_dir,
            check: true,
        )
    endif

    benchmark(
        t,
        python,
        args: [
            '@0@.py'.format(t),
            '--home',
            home_dir,
        ],
        env: run_env,
        depends: params.get('depends', []),
        suite: params.get('suite', ''),
        timeout: params.get('timeout', 60),
    )
endforeach
