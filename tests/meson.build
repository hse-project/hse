# TODO: On upgrade to 0.58, remove hse-python reference
# https://mesonbuild.com/Reference-manual.html#environment-object
if get_option('bindings-python')
    run_env.set(
        'PYTHONPATH',
        hse_python.get_variable('project_build_root'),
        meson.current_source_dir(),
    )
else
    run_env.set('PYTHONPATH', meson.current_source_dir())
endif

pytest = find_program('pytest', required: true)

if get_option('tests-dir') == ''
    tests_dir = meson.project_build_root() / 'hse-tests'
else
    tests_dir = get_option('tests-dir')
endif

if not fs.exists(tests_dir)
    run_command(
        'mkdir',
        tests_dir,
        check: true,
    )
endif

add_test_setup(
    'default',
    env: run_env,
    is_default: true,
    exclude_suites: ['ycsb'],
)

if 'unit' in enabled_tests
    subdir('unit')
endif
if 'functional' in enabled_tests
    subdir('functional')
endif

subdir('benchmarks')
