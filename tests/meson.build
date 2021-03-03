pytest = find_program('pytest', required: true)

path = run_command(
    'sh',
    '-c',
    'echo $PATH',
    check: true,
).stdout().strip()

path = '@0@:@1@:@2@:@3@'.format(
    cli_build_dir,
    samples_build_dir,
    tools_build_dir,
    path,
)

if get_option('mpool-bin-dir') != ''
    path = '@0@:@1@'.format(get_option('mpool-bin-dir'), path)
endif

run_env.set('PATH', path)

add_test_setup(
    'default',
    env: run_env,
    is_default: true,
)

subdir('unit')
subdir('functional')
