benchmarks_needs = 'bindings-python tests-kvdb tools'
benchmarks_enabled = (get_option('bindings-python') and
                       get_option('tests-kvdb') != '' and
                       get_option('tools'))

tests = {
    'test_kmt_ro.py': {
        'suite': 'kmt'
    },
    'test_kmt_rw.py': {
        'suite': 'kmt'
    },
    'test_ycsb_2tb_putget.py': {
        'suite': 'ycsb',
        'timeout': 0,
    },
    'test_ycsb_2tb_scan.py': {
        'suite': 'ycsb',
        'timeout': 0,
    },
    'test_dbbench.py': {
        'suite': 'dbbench',
        'timeout': 0,
    },
}

if not benchmarks_enabled
    warning(('HSE benchmarks disabled.'+
             '  Requires config options: @0@').format(benchmarks_needs))
else
    foreach t, params : tests
        path = meson.current_source_dir() / t
        testname = fs.stem(path)

        benchmark(
            testname,
            python,
            args: [
                path,
                '--kvdb',
                get_option('tests-kvdb'),
            ],
            env: run_env,
            suite: params.get('suite', ''),
            timeout: params.get('timeout', 60),
        )
    endforeach
endif
