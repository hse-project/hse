tests = {
    'kvdb_api_test': {},
    'transaction_api_test': {},
    'kvs_put_get_delete_api_test': {},
    'kvs_lifecycle_test': {},
    'cursor_api_test': {}
}

foreach t, params : tests
    t_exe = executable(
        t,
        [
            test_framework_sources,
            '@0@.c'.format(t),
            params.get('sources', []),
        ],
        c_args: params.get('c_args', []),
        include_directories: [
            hse_include_directories,
            test_framework_includes,
            tools_includes,
            params.get('include_directories', []),
        ],
        dependencies: [
            hse_static_dep,
            hse_dependencies,
            params.get('dependencies', [])
        ],
    )

    test(
        t,
        t_exe,
        args: params.get('args', []),
        env: params.get('env', environment()),
        is_parallel: params.get('is_parallel', true),
        suite: ['functional', 'api'] + params.get('suites', []),
        timeout: 300,
    )
endforeach
