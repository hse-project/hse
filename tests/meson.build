run_env.append('PYTHONPATH', meson.current_source_dir())

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

if 'unit' in hse_tests
    subdir('unit')
endif

if 'functional' in hse_tests
    subdir('functional')
endif

subdir('benchmarks')
