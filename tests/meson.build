run_env.append('PYTHONPATH', meson.current_source_dir())

test_runner = find_program('test-runner')
pytest = find_program('pytest')

# Suites to exclude based on varying factors
additional_suite_exclusions = []

if get_option('b_sanitize') != 'none'
    # Enabling hse-python based tests in sanitized builds needs to be
    # investigated. Issues with PYTHON_MALLOC_ and LD_PRELOAD.
    additional_suite_exclusions += 'python'
    additional_suite_exclusions += 'hse-python'

    if get_option('b_sanitize').contains('undefined')
        run_env.append('UBSAN_OPTIONS', 'suppressions=@0@/suppressions/hse.undefined.supp'.format(meson.project_source_root()))
        run_env.append('UBSAN_OPTIONS', 'print_stacktrace=1')
    endif
endif

add_test_setup(
    'default',
    exe_wrapper: [
        python,
        test_runner,
        '--',
    ],
    env: run_env,
    is_default: true,
    # TODO: Check with Meson 0.59 else PR to Meson...
    exclude_suites: ['long', 'non-deterministic', 'stress', 'stress_large'] + additional_suite_exclusions,
)

add_test_setup(
    'ci',
    exe_wrapper: [
        python,
        test_runner,
        '--',
    ],
    env: run_env,
    is_default: false,
    # TODO: Check with Meson 0.59 else PR to Meson...
    exclude_suites: ['long', 'smoke', 'non-deterministic', 'stress', 'stress_large'] + additional_suite_exclusions,
)

subdir('framework')
subdir('support')
subdir('fixtures')
subdir('mocks')

subdir('unit')
subdir('functional')
subdir('stress')
subdir('benchmarks')
