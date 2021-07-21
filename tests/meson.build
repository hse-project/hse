# TODO: On upgrade to 0.58, remove hse-python reference
# https://mesonbuild.com/Reference-manual.html#environment-object
if 'python' in bindings
    run_env.set(
        'PYTHONPATH',
        hse_python.get_variable('project_build_root'),
        meson.current_source_dir(),
    )
else
    run_env.set('PYTHONPATH', meson.current_source_dir())
endif

pytest = find_program('pytest', required: true)

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

if 'unit' in tests
    subdir('unit')
endif
if 'functional' in tests
    subdir('functional')
endif

subdir('benchmarks')
