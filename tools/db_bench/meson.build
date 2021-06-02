db_bench_cpp_args = [
    '-std=c++11',
    '-DHAVE_FREAD',
    '-DHAVE_FWRITE',
    '-DHAVE_FFLUSH',
    '-DHAVE_FSYNC',
    '-DLEVELDB_PLATFORM_POSIX',
    '-Wno-unused-parameter',
    '-Wno-sign-compare',
]

db_bench_dependencies = [
    hse_dependencies,
    hse_static_dep,
]

db_bench_include_directories = [
    hse_include_directories,
    include_directories('.'),
    include_directories('./include'),
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
    install: get_option('install-tools'),
    install_rpath: exe_install_rpath,
    gnu_symbol_visibility: 'hidden', 
)
