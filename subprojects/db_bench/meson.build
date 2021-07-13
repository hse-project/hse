project(
    'db_bench',
    ['cpp'],
    version: '1.0.0',
    license: [
        'BSD-3-Clause',
    ],
    default_options: [
        'prefix=/opt/hse',
        'buildtype=debugoptimized',
    ],
)
    
db_bench_cpp_args = [
    '-std=c++11',
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
    'hse-2',
    version: '>=2.0.0',
    required: true,
    fallback: ['hse', 'hse_dep'],
    default_options: [
        'cli=false',
        'tests=[]',
        'tools=false',
        'samples=false',
        'bindings-python=false',
    ],
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
