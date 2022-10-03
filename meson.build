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
        'force_fallback_for=lz4,cjson',
    ],
    meson_version: '>=0.61.0'
)

pkg = import('pkgconfig')
fs = import('fs')
cmake = import('cmake', required: false, disabler: true)

bash = find_program('bash', required: get_option('tests'))
sh = find_program('sh') # write POSIX-compliant when easily doable
getconf = find_program('getconf', required: false, native: true)

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
if in_git
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

if not meson.is_cross_build() and getconf.found()
    level1_dcache_linesize = run_command(
        getconf,
        'LEVEL1_DCACHE_LINESIZE',
        check: true
    ).stdout().strip()

    if level1_dcache_linesize.contains('undefined')
        level1_dcache_linesize = 64
    else
        level1_dcache_linesize = level1_dcache_linesize.to_int()
    endif
else
    level1_dcache_linesize = meson.get_external_property(
        'level1-dcache-linesize',
        64,
        native: not meson.is_cross_build()
    )
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
        '-DLOG_DEFAULT=@0@'.format(log_pri_default),
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
    ]
)
libyaml_dep = dependency(
    'yaml-0.1',
    version: '>=0.1.7',
    default_options: [
        'default_library=static',
        'warning_level=0',
        'werror=false',
    ]
)
thread_dep = dependency('threads')
liburcu_bp_dep = dependency(
    'liburcu-bp',
    version: '>=0.10.1',
    default_options: [
        'default_library=static',
        'warning_level=0',
        'werror=false',
    ]
)
libbsd_dep = dependency(
    'libbsd',
    version: '>=0.9.0',
    default_options: [
        'default_library=static',
        'warning_level=0',
        'werror=false',
    ]
)
liblz4_dep = dependency(
    'liblz4',
    version: ['>=1.9.2', '<2.0.0'],
    default_options: [
        'default_library=static',
        'warning_level=0',
        'werror=false',
    ]
)
xxhash_proj = subproject(
    'xxhash',
    default_options: [
        'default_library=static',
        'warning_level=0',
        'werror=false',
        'cli=false',
        'inline-all=true',
    ]
)
xxhash_dep = xxhash_proj.get_variable('xxhash_dep')
cjson_dep = dependency(
    'libcjson',
    version: ['>=1.7.14', '<2.0.0'],
    default_options: [
        'default_library=static',
        'warning_level=0',
        'werror=false',
        'tests=false',
    ]
)
cjson_utils_dep = dependency(
    'libcjson_utils',
    version: ['>=1.7.14', '<2.0.0'],
    default_options: [
        'default_library=static',
        'warning_level=0',
        'werror=false',
        'tests=false',
    ]
)
libmicrohttpd_dep = dependency(
    'libmicrohttpd',
    version: '>=0.9.59',
    default_options: [
        'default_library=static',
        'warning_level=0',
        'werror=false',
    ]
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
if not cc.has_header_symbol(
        'hdr/hdr_histogram.h',
        'hdr_record_value_atomic',
        dependencies: [HdrHistogram_c_dep])
    HdrHistogram_c_dep = disabler()
endif
HdrHistogram_c_can_fallback = get_option('wrap_mode') == 'forcefallback' or get_option('wrap_mode') != 'nofallback'
if cmake.found() and get_option('tools').allowed() and HdrHistogram_c_can_fallback and (not HdrHistogram_c_dep.found() or 'HdrHistogram_c' in get_option('force_fallback_for'))
    HdrHistogram_c_options = cmake.subproject_options()
    HdrHistogram_c_options.add_cmake_defines({
        'HDR_HISTOGRAM_BUILD_PROGRAMS': false,
        'HDR_HISTOGRAM_BUILD_SHARED': false,
        'HDR_HISTOGRAM_BUILD_STATIC': true,
        'HDR_LOG_REQUIRED': false,
    })
    HdrHistogram_c_options.set_override_option('werror', 'false')
    HdrHistogram_c_options.set_override_option('warning_level', '0')
    HdrHistogram_c_proj = cmake.subproject(
        'HdrHistogram_c',
        options: HdrHistogram_c_options,
        required: get_option('tools')
    )
    if HdrHistogram_c_proj.found()
        HdrHistogram_c_dep = HdrHistogram_c_proj.dependency('hdr_histogram_static')
    else
        HdrHistogram_c_dep = disabler()
    endif
endif
libmongoc_dep = dependency(
    'libmongoc-1.0',
    version: ['>=1.17.3', '<1.21.0'],
    required: false,
    disabler: true
)
libbson_dep = dependency(
    'libbson-1.0',
    version: ['>=1.17.3', '<1.21.0'],
    required: false,
    disabler: true
)
mongo_c_driver_can_fallback = get_option('wrap_mode') == 'forcefallback' or get_option('wrap_mode') != 'nofallback'
if cmake.found() and get_option('tools').allowed() and mongo_c_driver_can_fallback and ((not libmongoc_dep.found() or not libbson_dep.found()) or 'mongo-c-driver' in get_option('force_fallback_for'))
    mongo_c_driver_options = cmake.subproject_options()
    mongo_c_driver_options.add_cmake_defines({
        'ENABLE_TESTS': false,
        'ENABLE_EXAMPLES': false,
        'ENABLE_SSL': 'OFF',
        'ENABLE_MONGODB_AWS_AUTH': 'OFF',
        'ENABLE_MONGOC': not libmongoc_dep.found() or mongo_c_driver_can_fallback ? 'ON' : 'OFF',
        'ENABLE_BSON': not libbson_dep.found() or mongo_c_driver_can_fallback ? 'ON' : 'OFF',
        'ENABLE_STATIC': 'ON',
        'ENABLE_AUTOMATIC_INIT_AND_CLEANUP': false,
    })
    mongo_c_driver_options.set_override_option('werror', 'false')
    mongo_c_driver_options.set_override_option('warning_level', '0')
    mongo_c_driver_proj = cmake.subproject(
        'mongo-c-driver',
        options: mongo_c_driver_options,
        required: get_option('tools')
    )
    if not libmongoc_dep.found() or mongo_c_driver_can_fallback
        if mongo_c_driver_proj.found()
            libmongoc_dep = [
                mongo_c_driver_proj.dependency('mongoc_static'),
                cc.find_library('resolv'),
            ]
        else
            libmongoc_dep = disabler()
        endif
    endif
    if not libbson_dep.found() or mongo_c_driver_can_fallback
        if mongo_c_driver_proj.found()
            libbson_dep = mongo_c_driver_proj.dependency('bson_static')
        else
            libbson_dep = disabler()
        endif
    endif
else
    libbson_dep = disabler()
    libmongoc_dep = disabler()
endif

bindings = []
if 'all' in get_option('bindings')
    assert(get_option('bindings').length() == 1, 'The -Dbindings=all option cannot have additional values')

    bindings += 'java'
    bindings += 'python'
elif 'none' in get_option('bindings')
    assert(get_option('bindings').length() == 1, 'The -Dbindings=none option cannot have additional values')
elif 'auto' in get_option('bindings')
    assert(get_option('bindings').length() == 1, 'The -Dbindings=auto option cannot have additional values')

    bindings = get_option('bindings')
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
    check: true
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

hse_java_depends = disabler()
if 'java' in bindings or 'auto' in bindings
    hse_java = subproject(
        'hse-java',
        required: 'java' in bindings,
        default_options: [
            'docs=disabled',
            'tests=@0@'.format(get_option('tests')),
        ]
    )

    if hse_java.found()
        hsejni = hse_java.get_variable('hsejni')
        hse_jar = hse_java.get_variable('hse_jar')

        hse_java_depends = [
            hsejni,
            hse_jar,
        ]
    endif
else
    hse_java = disabler()
endif

hse_python_depends = disabler()
if 'python' in bindings or 'auto' in bindings
    hse_python = subproject(
        'hse-python',
        required: 'python' in bindings,
        default_options: [
            'tests=@0@'.format(get_option('tests')),
        ]
    )

    if hse_python.found()
        hse_python_depends = hse_python.get_variable('extension_modules')
        run_env.prepend('PYTHONPATH', hse_python.get_variable('project_build_root'))
    endif
else
    hse_python = disabler()
endif

subdir('tools')

run_env.prepend('PATH', executable_paths)

if get_option('tests')
    subdir('tests')
endif

format = find_program('scripts/dev/format.sh')
run_target(
    'format',
    command: [
        format,
    ]
)
run_target(
    'format-check',
    command: [
        format,
        '-c',
    ]
)

run_target(
    'checkoss',
    command: [
        find_program('scripts/dev/checkoss.sh'),
        '@BUILD_ROOT@',
        '@SOURCE_ROOT@',
    ]
)

if not meson.is_subproject()
    if in_git
        run_target(
            'git-hooks',
            command: [
                find_program('scripts/git-hooks/link.sh'),
            ]
        )
    endif
endif

clang_tidy = find_program('clang-tidy', required: false)
if clang_tidy.found() and cc.get_id() == 'clang'
    run_target(
        'clang-tidy',
        command: [
            find_program('scripts/dev/clang-tidy.sh'),
        ]
    )
endif

shellcheck = find_program('shellcheck', required: false)
if shellcheck.found()
    run_target(
        'shellcheck',
        command: [
            find_program('scripts/dev/shellcheck.sh'),
        ]
    )
endif

if get_option('b_coverage') and get_option('tests')
    gcovr = find_program('gcovr', required: get_option('b_coverage'), disabler: true)

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
                gcovr,
                '-r',
                '@SOURCE_ROOT@',
                '@BUILD_ROOT@',
                args,
                '@BUILD_ROOT@/@OUTPUT@',
                '-f',
                '@SOURCE_ROOT@/lib'
            ],
            depends: unit_test_exes,
            output: 'coverage.@0@'.format(type)
        )
    endforeach
endif
