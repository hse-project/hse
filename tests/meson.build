run_env.prepend('PYTHONPATH', meson.current_source_dir())

test_runner = find_program('test-runner')

# Suites to exclude based on varying factors
additional_suite_exclusions = []

if get_option('b_sanitize') != 'none'
    # Enabling hse-python and hse-java based tests in sanitized builds needs to
    # be investigated. Issues with PYTHON_MALLOC_ and LD_PRELOAD.
    additional_suite_exclusions += 'hse-java'
    additional_suite_exclusions += 'python'
    additional_suite_exclusions += 'hse-python'

    if get_option('b_sanitize').contains('undefined')
        run_env.append('UBSAN_OPTIONS', 'suppressions=@0@/suppressions/hse.undefined.supp'.format(meson.project_source_root()))
        run_env.append('UBSAN_OPTIONS', 'print_stacktrace=1')
    endif
endif

wrapper = [
    python,
    test_runner,
    '--',
]

add_test_setup(
    'default',
    exe_wrapper: wrapper,
    env: run_env,
    is_default: not meson.is_subproject(),
    exclude_suites: ['long', 'non-deterministic', 'stress', 'stress-large', 'nightly-small'] + additional_suite_exclusions
)

add_test_setup(
    'all',
    exe_wrapper: wrapper,
    env: run_env,
    is_default: false
)

add_test_setup(
    'ci',
    exe_wrapper: wrapper,
    env: run_env,
    is_default: false,
    exclude_suites: ['long', 'smoke', 'non-deterministic', 'stress', 'stress-large', 'nightly-small'] + additional_suite_exclusions
)

subdir('framework')
subdir('support')
subdir('fixtures')
subdir('mocks')

subdir('unit')
subdir('functional')
subdir('stress')
subdir('benchmarks')
