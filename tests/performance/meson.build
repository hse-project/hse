performance_needs = 'tests-kvdb bindings-python tools'
performance_enabled = (get_option('bindings-python') and
                       get_option('tests-kvdb') != '' and
                       get_option('tools'))

tests = [
    'test_kmt_ro.py',
    'test_kmt_rw.py',
]

nomalloc = environment({'MALLOC_PERTURB_': '0'})

log_root = meson.project_source_root() / 'logs' / 'performance'

if not performance_enabled
    warning(('HSE performance test suite disabled.'+
             '  Requires config options: @0@').format(performance_needs))
else
    foreach t : tests
        path = meson.current_source_dir() / t
        testname = fs.stem(path)

        log_dir = log_root / testname

        test(
            testname,
            python,
            env: nomalloc,
            args: [
                path,
                '--kvdb',
                get_option('tests-kvdb'),
                '--log-dir',
                log_dir,
            ],
            is_parallel: false,
            suite: ['performance'],
            timeout: 60,
        )
    endforeach
endif
