project(
    'db_bench',
    ['cpp'],
    version: '1.0.0',
    license: [
        'BSD-3-Clause',
    ],
    default_options: [
        'b_ndebug=if-release',
        'cpp_std=c++11',
        'buildtype=debugoptimized',
        'warning_level=2',
    ],
)

# meson does not appear to be able to use subproject's
# compile flags specified via default option.
add_project_arguments('-std=c++11', language: 'cpp' )

db_bench_cpp_args = [
    '-DHSE_EXPERIMENTAL',
    '-DHAVE_FREAD',
    '-DHAVE_FWRITE',
    '-DHAVE_FFLUSH',
    '-DHAVE_FSYNC',
    '-DLEVELDB_PLATFORM_POSIX',
    '-Wno-unused-parameter',
    '-Wno-sign-compare',
]

hse_dep = dependency(
    'hse-2-static',
    required: true,
)

threads_dep = dependency(
    'threads',
    required: true
)

db_bench_dependencies = [
    hse_dep,
    threads_dep,
]

db_bench_include_directories = [
    include_directories('.'),
    include_directories('include'),
]

db_bench_sources = files(
    'benchmarks/db_bench.cc',
    'hse_binding/hse_kvdb.cc',
    'hse_binding/hse_kvs.cc',
    'hse_binding/hse_kvs_cursor.cc',
    'util/histogram.cc',
    'util/status.cc',
    'util/testutil.cc',
)

executable(
    'db_bench',
    db_bench_sources,
    cpp_args: db_bench_cpp_args,
    include_directories: db_bench_include_directories,
    dependencies: db_bench_dependencies,
    install: true,
    gnu_symbol_visibility: 'hidden',
)
