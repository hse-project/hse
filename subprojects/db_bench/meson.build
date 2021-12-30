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

cpp = meson.get_compiler('cpp')

hse_dep = dependency('hse-2')
threads_dep = dependency('threads')

add_project_arguments(
    cpp.get_supported_arguments([
        '-DHAVE_FREAD',
        '-DHAVE_FWRITE',
        '-DHAVE_FFLUSH',
        '-DHAVE_FSYNC',
        '-DLEVELDB_PLATFORM_POSIX',
        '-Wno-unused-parameter',
        '-Wno-sign-compare',
    ]),
    language: 'cpp'
)

db_bench = executable(
    'db_bench',
    files(
        'benchmarks/db_bench.cc',
        'hse_binding/hse_kvdb.cc',
        'hse_binding/hse_kvs.cc',
        'hse_binding/hse_kvs_cursor.cc',
        'util/histogram.cc',
        'util/status.cc',
        'util/testutil.cc',
    ),
    include_directories: [
        include_directories('.'),
        include_directories('include'),
    ],
    dependencies: [
        hse_dep,
        threads_dep,
    ],
    install: true,
    gnu_symbol_visibility: 'hidden',
)
