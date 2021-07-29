subdir('kvpy')
subdir('smoke')
subdir('api')

tests = {
    'kvs_compare_full_and_pfx': {
        'suites': ['long'],
        'depends': hse_python_depends,
    },
    'kvs_scan_deleted_keys': {
        'suites': ['short'],
        'depends': hse_python_depends,
    },
    'kvs_scan_empty_kvs': {
        'suites': ['short'],
        'depends': hse_python_depends,
    },
    # [HSE_TODO]: Invalid tests
    # 'kvs_compressed_values_take_less_space': {
    #     'suites': ['short'],
    #     'depends': hse_python_depends,
    # },
    # 'kvs_compression_flags': {
    #     'suites': ['short'],
    #     'depends': hse_python_depends,
    # },
    'kvs_scan_a_billion': {
        'suites': ['long'],
        'depends': hse_python_depends,
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

    test(
        t,
        python,
        args: [
            '@0@.py'.format(t),
            '--home',
            home_dir,
        ],
        workdir: meson.current_source_dir(),
        depends: params.get('depends', []),
        suite: ['functional', 'python'] + params.get('suites', []),
        timeout: 3600,
    )
endforeach
