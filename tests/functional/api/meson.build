common_test_c_args = [
    '-D_GNU_SOURCE=1',
    '-DCOMPNAME="kvdb"',
]

common_test_includes = [
    hse_include_directories,
    test_framework_includes,
    tools_includes,
    get_option('mpool-include-dir'),
]

common_test_sources = []

common_test_dependencies = [
    hse_static_dep,
]

tests = {
    'kvdb_api_test':{
        'args': [
            get_option('tests-kvdb')
        ]
    },
}

foreach t, params : tests
    t_sources = common_test_sources
    t_sources += '@0@.c'.format(t)
    if 'sources' in params
        t_sources += params['sources']
    endif

    t_c_args = common_test_c_args
    if 'c_args' in params
        t_c_args += params['c_args']
    endif

    t_include_directories = common_test_includes
    if 'include_directories' in params
        t_include_directories += params['include_directories']
    endif

    t_dependencies = common_test_dependencies
    if 'dependencies' in params
        t_dependencies += params['dependencies']
    endif

    t_exe = executable(
        t,
        t_sources,
        c_args: t_c_args,
        include_directories: t_include_directories,
        dependencies: t_dependencies,
    )

    t_suites = ['functional', 'api']
    if 'suites' in params
        t_suites += params['suites']
    endif

    t_env = 'env' in params ? environment(params['env']) : environment()

    t_is_parallel = 'is_parallel' in params ? params['is_parallel'] : true

    if 'cases' in params
        foreach ident, args : params['cases']
            t_name = ident == 'default' ? t : '@0@[@1@]'.format(t, ident)

            test(
                t_name,
                t_exe,
                args: args,
                env: t_env,
                is_parallel: t_is_parallel,
                suite: t_suites,
            )
        endforeach
    else
        t_args = []
        if 'args' in params
            t_args += params['args']
        endif

        test(
            t,
            t_exe,
            args: t_args,
            env: t_env,
            is_parallel: t_is_parallel,
            suite: t_suites,
        )
    endif
endforeach
