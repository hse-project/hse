project(
    'hse',
    ['c'],
    version: files('VERSION'),
    license: 'Apache-2.0',
    default_options: [
        'prefix=/opt/hse',
        'b_ndebug=if-release',
        'c_std=gnu11',
        'buildtype=debugoptimized',
        'warning_level=2',
        'force_fallback_for=xxhash,lz4,cjson',
    ],
    meson_version: '>=0.58.0',
)

pkg = import('pkgconfig')
fs = import('fs')
cmake = import('cmake')

bash = find_program('bash')
sh = find_program('sh') # write POSIX-compliant when easily doable

ci = run_command(sh, '-c', '[ ${CI+x} ]', check: false).returncode() == 0

cc = meson.get_compiler('c')
python = find_program('python3')

version_components = meson.project_version().split('.')

hse_major_version = version_components[0]
hse_minor_version = version_components[1]
hse_patch_version = version_components[2]

if ci
    add_project_arguments('-DHSE_CI', language: 'c')
endif

# Compute the relative path used by compiler invocations.
relative_dir = run_command(
    python,
    '-c',
    'import os; print("{}/".format(os.path.relpath("@0@", "@1@")))'.format(
        meson.project_source_root(),
        meson.global_build_root(),
    ),
    check: true,
).stdout().strip()

# Strip relative path prefixes from the code if possible, otherwise hide them.
# The following snippet is inspired by the SwayWM Project under the MIT license.
add_project_arguments(
    cc.first_supported_argument([
        '-fmacro-prefix-map=@0@='.format(relative_dir),
        '-DHSE_REL_SRC_DIR="@0@"'.format(relative_dir),
    ]),
    language: 'c'
)

if get_option('b_sanitize').contains('undefined')
    add_project_arguments(
        cc.get_supported_arguments([
            '-fno-sanitize-recover=undefined',
            '-fsanitize-recover=alignment',
        ]),
        language: 'c'
    )
endif

git = find_program('git', required: false)
in_git = git.found() and run_command(git, 'rev-parse', check: false).returncode() == 0
if not meson.is_subproject() and in_git
    build_version = run_command(
        git,
        'describe',
        '--always',
        '--long',
        '--dirty',
        check: true
    ).stdout().strip()
else
    build_version = meson.project_version()
endif

if get_option('debug')
    log_pri_default = 7

    if get_option('buildtype') == 'debug'
        add_project_arguments(
            cc.get_supported_arguments([
                '-DDEBUG_RCU',
                '-fstack-protector-all',
            ]),
            language: 'c',
        )
    endif

    add_project_arguments(
        '-DHSE_BUILD_DEBUG',
        language: 'c',
    )
else
    log_pri_default = 6

    add_project_arguments(
        '-DHSE_BUILD_RELEASE',
        language: 'c',
    )
endif

level1_dcache_linesize = run_command(
    'getconf',
    'LEVEL1_DCACHE_LINESIZE',
    check: true
).stdout().strip()

if level1_dcache_linesize.contains('undefined')
   level1_dcache_linesize = 64
endif

if get_option('omf-byte-order') != 'native'
    add_project_arguments(
        '-DHSE_OMF_BYTE_ORDER=__ORDER_@0@_ENDIAN__'.format(
            get_option('omf-byte-order').to_upper()),
        language: 'c'
    )
endif

add_project_arguments(
    cc.get_supported_arguments([
        '-D_GNU_SOURCE',
        '-D_LGPL_SOURCE',
        '-Wlogical-op',
        '-Wno-missing-field-initializers',
        '-Wmaybe-uninitialized',
        '-Wno-sign-compare',
        '-Wno-unused-parameter',
        '-DHSE_LOGPRI_DEFAULT=@0@'.format(log_pri_default),
        '-DLEVEL1_DCACHE_LINESIZE=@0@'.format(level1_dcache_linesize),
        '-DURCU_INLINE_SMALL_FUNCTIONS',
    ]),
    language: 'c'
)

libcurl_dep = dependency(
    'libcurl',
    version: '>=7.58.0',
    fallback: 'curl',
    default_options: [
        'default_library=static',
        'warning_level=0',
        'werror=false',
    ],
)
libyaml_dep = dependency(
    'yaml-0.1',
    version: '>=0.1.7',
    fallback: 'libyaml',
    default_options: [
        'default_library=static',
        'warning_level=0',
        'werror=false',
    ],
)
thread_dep = dependency('threads')
liburcu_bp_dep = dependency(
    'liburcu-bp',
    version: '>=0.10.1',
    fallback: 'userspace-rcu',
    default_options: [
        'default_library=static',
        'warning_level=0',
        'werror=false',
    ],
)
libbsd_dep = dependency(
    'libbsd',
    version: '>=0.9.0',
    fallback: 'libbsd',
    default_options: [
        'default_library=static',
        'warning_level=0',
        'werror=false',
    ],
)
liblz4_dep = dependency(
    'liblz4',
    version: '>=1.9.2',
    fallback: ['lz4', 'liblz4_dep'],
    default_options: [
        'default_library=static',
        'warning_level=0',
        'werror=false',
    ],
)
xxhash_dep = dependency(
    'libxxhash',
    version: '>=0.8.0',
    fallback: ['xxhash', 'xxhash_dep'],
    default_options: [
        'default_library=static',
        'warning_level=0',
        'werror=false',
        'cli=false',
        'inline-all=true',
    ],
)
cjson_dep = dependency(
    'libcjson',
    version: '>=1.7.14',
    fallback: 'cjson',
    default_options: [
        'default_library=static',
        'warning_level=0',
        'werror=false',
        'tests=false',
    ],
)
libmicrohttpd_dep = dependency(
    'libmicrohttpd',
    version: '>=0.9.59',
    fallback: 'libmicrohttpd',
    default_options: [
        'default_library=static',
        'warning_level=0',
        'werror=false',
    ],
)
libpmem_dep = dependency('libpmem', version: '>= 1.4.0', required: get_option('pmem'))
m_dep = cc.find_library('m')
crc32c_proj = subproject(
    'crc32c',
    default_options: [
        'default_library=static',
        'warning_level=0',
        'werror=false',
    ]
)
crc32c_dep = crc32c_proj.get_variable('crc32c_dep')
hyperloglog_proj = subproject('hyperloglog')
hyperloglog_dep = hyperloglog_proj.get_variable('hyperloglog_dep')
rbtree_proj = subproject(
    'rbtree',
    default_options: [
        'default_library=static',
        'warning_level=0',
        'werror=false',
    ]
)
rbtree_dep = rbtree_proj.get_variable('rbtree_dep')
xoroshiro_proj = subproject('xoroshiro')
xoroshiro_dep = xoroshiro_proj.get_variable('xoroshiro_dep')
ncurses_dep = dependency('ncurses', version: '>= 6.1.20180127', required: get_option('tools'))
HdrHistogram_c_dep = cc.find_library('hdr_histogram', required: false, disabler: true)
if not get_option('tools').disabled() and (not HdrHistogram_c_dep.found()
        or (HdrHistogram_c_dep.found() and not cc.has_header_symbol(
            'hdr/hdr_histogram.h',
            'hdr_record_value_atomic',
            dependencies: [HdrHistogram_c_dep]))
        or get_option('wrap_mode') == 'forcefallback'
        or 'HdrHistogram_c' in get_option('force_fallback_for'))
    HdrHistogram_c_options = cmake.subproject_options()
    HdrHistogram_c_options.add_cmake_defines({
        'HDR_HISTOGRAM_BUILD_PROGRAMS': false,
        'HDR_HISTOGRAM_BUILD_SHARED': false,
        'HDR_HISTOGRAM_BUILD_STATIC': true,
        'HDR_LOG_REQUIRED': false,
    })
    HdrHistogram_c_options.set_override_option('werror', 'false')
    HdrHistogram_c_options.set_override_option('warning_level', '0')
    HdrHistogram_c_proj = cmake.subproject('HdrHistogram_c', options: HdrHistogram_c_options)
    HdrHistogram_c_dep = HdrHistogram_c_proj.dependency('hdr_histogram_static')
endif
libmongoc_dep = dependency('libmongoc-1.0', version: '>=1.17.3', required: false)
libbson_dep = dependency('libbson-1.0', version: '>=1.17.3', required: false)
mongo_c_driver_force_fallback = get_option('wrap_mode') == 'forcefallback' or 'mongo-c-driver' in get_option('force_fallback_for')
if not get_option('tools').disabled() and (not libmongoc_dep.found()
        or not libbson_dep.found() or mongo_c_driver_force_fallback)
    mongo_c_driver_options = cmake.subproject_options()
    mongo_c_driver_options.add_cmake_defines({
        'ENABLE_TESTS': false,
        'ENABLE_EXAMPLES': false,
        'ENABLE_SSL': 'OFF',
        'ENABLE_MONGODB_AWS_AUTH': 'OFF',
        'ENABLE_MONGOC': not libmongoc_dep.found() or mongo_c_driver_force_fallback ? 'ON' : 'OFF',
        'ENABLE_BSON': not libbson_dep.found() or mongo_c_driver_force_fallback ? 'ON' : 'OFF',
        'ENABLE_STATIC': 'ON',
        'ENABLE_AUTOMATIC_INIT_AND_CLEANUP': false,
        'BUILD_VERSION': '1.17.3',
    })
    mongo_c_driver_options.set_override_option('werror', 'false')
    mongo_c_driver_options.set_override_option('warning_level', '0')
    mongo_c_driver_proj = cmake.subproject('mongo-c-driver', options: mongo_c_driver_options)
    if not libmongoc_dep.found() or mongo_c_driver_force_fallback
        libmongoc_dep = [
            mongo_c_driver_proj.dependency('mongoc_static'),
            cc.find_library('resolv'),
        ]
    endif
    if not libbson_dep.found() or mongo_c_driver_force_fallback
        libbson_dep = mongo_c_driver_proj.dependency('bson_static')
    endif
endif

bindings = []
if 'all' in get_option('bindings')
    assert(get_option('bindings').length() == 1, 'The -Dbindings=all option cannot have additional values')
    bindings += 'python'
elif 'none' in get_option('bindings')
    assert(get_option('bindings').length() == 1, 'The -Dbindings=none option cannot have additional values')
elif 'auto' in get_option('bindings')
    assert(get_option('bindings').length() == 1, 'The -Dbindings=auto option cannot have additional values')

    # Determine whether we can build hse-ython
    cython_verison_res = run_command(
        python,
        '-c',
        'from Cython.Compiler.Version import version; print(version)',
        check: false
    )
    if cython_verison_res.returncode() == 0
        if cython_verison_res.stdout().strip().version_compare('>=0.29.21')
            bindings += 'python'
        endif
    endif
else
    bindings = get_option('bindings')
endif

# Add paths to these variables if you want to see targets in the runtime
# environment
executable_paths = []
library_paths = []

bindir_to_libdir = run_command(
    python,
    '-c',
    'import os; print("{}/".format(os.path.relpath("@0@", "@1@")))'.format(
        get_option('prefix') / get_option('libdir'),
        get_option('prefix') / get_option('bindir'),
    ),
    check: true,
).stdout().strip()

rpath = get_option('rpath') ? '$ORIGIN' / bindir_to_libdir : ''

if get_option('tests')
    find_program('gawk')
    mapi_idx_generate = find_program('scripts/build/mapi_idx_generate.sh')
    ut_mock_decl_files = find_program('scripts/build/ut_mock_decl_files.sh')
    utpp = find_program('scripts/build/utpp')
endif

subdir('include')
if get_option('tests') or not get_option('tools').disabled()
    # need access to tools_includes for unit tests and tools
    subdir('tools/include')
endif
subdir('lib')
subdir('cli')
subdir('samples')
subdir('docs')

# Environment in which various run_targets and tests will run in
run_env = environment()

if 'python' in bindings
    hse_python = subproject(
        'hse-python',
        default_options: [
            'tests=@0@'.format(get_option('tests')),
        ]
    )

    hse_python_depends = hse_python.get_variable('extension_modules')
    run_env.set('PYTHONPATH', hse_python.get_variable('project_build_root'))

    run_target(
        'python-repl',
        command: [
            python,
        ],
        depends: hse_python_depends,
        env: run_env,
    )
else
    hse_python_depends = disabler()
endif

if get_option('db_bench') and get_option('experimental')
    db_bench_proj = subproject(
        'db_bench',
        default_options: [
            'cpp_std=c++11',
        ]
    )
    db_bench = db_bench_proj.get_variable('db_bench')
    executable_paths += fs.parent(db_bench.full_path())
else
    db_bench = disabler()
endif

subdir('tools')

run_env.prepend('PATH', executable_paths)

if get_option('tests')
    subdir('tests')
endif

if get_option('ycsb')
    subdir('hsejni')
endif

format = find_program('scripts/dev/format.sh')
run_target(
    'format',
    command: [
        format,
    ],
)
run_target(
    'format-check',
    command: [
        format,
        '-c',
    ],
)

if not meson.is_subproject()
    if in_git
        run_target(
            'git-hooks',
            command: [
                find_program('scripts/git-hooks/link.sh'),
            ],
        )
    endif
endif

run_target(
    'checkoss',
    command: [
        find_program('scripts/dev/checkoss.sh'),
        '@BUILD_ROOT@',
        '@SOURCE_ROOT@',
    ],
)

shellcheck = find_program('shellcheck', required: false)
if shellcheck.found()
    run_target(
        'shellcheck',
        command: [
            find_program('scripts/dev/shellcheck.sh'),
        ]
    )
endif

gcovr = find_program('gcovr', required: get_option('b_coverage'))
if gcovr.found() and get_option('b_coverage') and get_option('tests')
    reports = {
        'text': [ '-o' ],
        'html': [ '--html', '--html-details', '-o' ],
        'json': [ '--json-summary-pretty', '-o' ],
        'xml': [ '--sonarqube' ],
    }

    foreach type, args : reports
        custom_target(
            'gcovr-@0@'.format(type),
            command: [
                'gcovr',
                '-r',
                '@SOURCE_ROOT@',
                '@BUILD_ROOT@/lib',
                args,
                '@OUTPUT@',
                '-f',
                '@SOURCE_ROOT@/lib'
            ],
            depends: unit_test_exes,
            output: 'coverage.@0@'.format(type)
        )
    endforeach
endif
