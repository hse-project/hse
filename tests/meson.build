pytest = find_program('pytest', required: true)

add_test_setup(
    'default',
    env: python_env,
    is_default: true,
)

subdir('unit')
subdir('functional')
