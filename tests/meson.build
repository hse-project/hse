pytest = find_program('pytest', required: true)

add_test_setup(
    'default',
    env: run_env,
    is_default: true,
)

if 'unit' in enabled_tests
    subdir('unit')
endif
if 'functional' in enabled_tests
    subdir('functional')
endif

subdir('benchmarks')
