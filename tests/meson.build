pytest = find_program('pytest', required: true)

add_test_setup(
    'default',
    env: run_env,
    is_default: true,
)

if unit_tests_enabled
    subdir('unit')
endif
if functional_tests_enabled
    subdir('functional')
endif
