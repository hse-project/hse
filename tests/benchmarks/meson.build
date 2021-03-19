benchmarks_needs = 'bindings-python tests-kvdb tools'
benchmarks_enabled = (get_option('bindings-python') and
                       get_option('tests-kvdb') != '' and
                       get_option('tools'))

tests = [
    'test_kmt_ro.py',
    'test_kmt_rw.py',
]

log_root = get_option('benchmarks-log-dir')
if log_root == ''
    log_root = meson.project_build_root() / 'benchmark-logs'
endif

if not benchmarks_enabled
    warning(('HSE benchmarks disabled.'+
             '  Requires config options: @0@').format(benchmarks_needs))
else
    foreach t : tests
        path = meson.current_source_dir() / t
        testname = fs.stem(path)

        log_dir = log_root / testname

        benchmark(
            testname,
            python,
            args: [
                path,
                '--kvdb',
                get_option('tests-kvdb'),
                '--log-dir',
                log_dir,
            ],
            env: run_env,
            timeout: 60,
        )
    endforeach
endif
