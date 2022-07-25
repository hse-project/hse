libclang_dep = dependency(
    'Clang',
    method: 'cmake',
    modules: ['libclang'],
    native: true
)

clang = find_program('clang')
clang_resource_dir = run_command(
    'clang',
    '-print-resource-dir',
    check: true
).stdout().strip()
clang_include_dir = clang_resource_dir / 'include'

message(clang_include_dir)

mkmock = executable(
    'mkmock',
    'mkmock.c',
    'mock.c',
    'commands/header.c',
    'commands/source.c',
    'commands/symbol-table.c',
    include_directories: [
        include_directories('.'),
        util_includes,
    ],
    dependencies: [
        libclang_dep,
    ],
    native: true
)
