subdir('kvpy')
subdir('smoke')
subdir('api')

functional_needs = ['bindings-python', 'tests-kvdb', 'tools']

if not (get_option('bindings-python') and
           get_option('tests-kvdb') != '' and
           get_option('tools'))
    warning(('HSE functional test suite short and long disabled.'+
         '  Requires config options: @0@').format(', '.join(functional_needs)))
    subdir_done()
endif

tests = {
    'kvs_compare_full_and_pfx': {
        'suites': ['short'],
    },
    'kvs_scan_deleted_keys': {
        'suites': ['short'],
    },
    'kvs_scan_empty_kvs': {
        'suites': ['short'],
    },
    'kvs_compression_same_mpool': {
    'suites': ['short'],
    },
    'longtest_cursor_variable_prefix': {
    'suites': ['long'],
    },
    'kvs_scan_a_billion': {
        'suites': ['long'],
    },
}

foreach t, params : tests
    t_suites = ['functional']

    if 'suites' in params
        t_suites += params['suites']
    endif

    test(
        t,
        python,
        args: [
            '@0@.py'.format(t),
            get_option('tests-kvdb'),
        ],
        depends: hse_python_depends,
        workdir: meson.current_source_dir(),
        timeout: 3600,
        is_parallel: false,
        suite: t_suites,
    )
endforeach
