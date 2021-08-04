run_env.append('PYTHONPATH', meson.current_source_dir())

pytest = find_program('pytest', required: true)
bash = find_program('bash')
sh = find_program('sh') # write POSIX-compliant when easily doable

if not fs.exists(tests_dir)
    run_command(
        'mkdir',
        tests_dir,
        check: true,
    )
endif

# Suites to exclude based on varying factors
additional_suite_exclusions = []

if get_option('b_sanitize') != 'none'
    # Enabling hse-python based tests in sanitized builds needs to be
    # investigated. Issues with PYTHON_MALLOC_ and LD_PRELOAD.
    additional_suite_exclusions += 'python'
    additional_suite_exclusions += 'hse-python'

    run_env.set('UBSAN_OPTIONS', 'suppressions=@0@/hse.undefined.supp'.format(meson.project_source_root()))
endif

add_test_setup(
    'default',
    env: run_env,
    is_default: true,
    # TODO: Check with Meson 0.59 else PR to Meson...
    exclude_suites: ['long', 'non-deterministic'] + additional_suite_exclusions,
)

add_test_setup(
    'ci',
    env: run_env,
    is_default: false,
    # TODO: Check with Meson 0.59 else PR to Meson...
    exclude_suites: ['long', 'smoke', 'non-deterministic'] + additional_suite_exclusions,
)

subdir('unit')
subdir('functional')
subdir('benchmarks')
