project(
    'hse',
    ['c'],
    version: '2.0.0',
    license: [
        'Apache-2.0',
    ],
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
pymod = import('python')

cc = meson.get_compiler('c')
python = pymod.find_installation(
    'python3',
    required: true,
)

version_components = meson.project_version().split('.')

hse_major_version = version_components[0]
hse_minor_version = version_components[1]
hse_patch_version = version_components[2]

if meson.version().version_compare('>=0.58.0')
    global_build_root = meson.global_build_root()
else
    global_build_root = meson.build_root()
endif

# Compute the relative path used by compiler invocations.
relative_dir = run_command(
    python,
    '-c',
    'import os; print("{}/".format(os.path.relpath("@0@", "@1@")))'.format(
        meson.project_source_root(),
        global_build_root,
    ),
    check: true,
).stdout().strip()

# Strip relative path prefixes from the code if possible, otherwise hide them.
# The following snippet is attributed to the SwayWM Project under the MIT license.
if cc.has_argument('-fmacro-prefix-map=/prefix/to/hide=')
	add_project_arguments(
		'-fmacro-prefix-map=@0@='.format(relative_dir),
		language: 'c'
	)
else
	add_project_arguments(
		'-DHSE_REL_SRC_DIR="@0@"'.format(relative_dir),
		language: 'c'
	)
endif

if get_option('b_sanitize').contains('undefined')
    if cc.has_argument('-fno-sanitize-recover=undefinded') and cc.has_argument('-fsanitize-recover=alignment')
        add_project_arguments(
            '-fno-sanitize-recover=undefinded',
            '-fsanitize-recover=alignment',
            language: 'c'
        )
    endif
endif

git = find_program('git', required: false)
if git.found() and fs.exists(meson.project_source_root() / '.git')
    build_tag = run_command(
        git,
        'describe',
        '--always',
        '--long',
        '--tags',
        '--dirty',
        '--abbrev=10',
        check: true
    ).stdout().strip()

    build_sha = run_command(
        git,
        'rev-parse',
        'HEAD',
        check: true
    ).stdout().strip()
elif fs.exists(meson.project_source_root() / 'VERSION')
    version_file_components = fs.read(meson.project_source_root() / 'VERSION').stdout().strip().split('\n')

    build_tag = version_file_components[0]
    build_sha = version_file_components[1]
else
    build_tag = 'unknown'
    build_sha = 'unknown'
endif

if build_tag != 'unknown'
    build_rel = run_command(
        'sh',
        '-c',
        'echo @0@ | sed --quiet --regexp-extended "s/.*-([0-9]+)-[a-z0-9]{7,}(-dirty){0,1}$/\\1/p"'
            .format(build_tag),
        check: true,
    ).stdout().strip()
    build_vqual = run_command(
        'sh',
        '-c',
        'echo @0@ | sed --quiet --regexp-extended "s/.*-([^-]+)-[0-9]+-[a-z0-9]{7,}(-dirty){0,1}$/~\\1/p"'
            .format(build_tag),
        check: true,
    ).stdout().strip()
else
    build_rel = 'unknown'
    build_vqual = 'unknown'
endif

log_pri_default = 5
if get_option('buildtype') == 'release'
    if get_option('optimization') == 'g'
        build_stype = 'i'
    else
        build_stype = 'r'
    endif

    add_project_arguments(
        '-DHSE_BUILD_RELEASE',
        language: 'c',
    )
elif get_option('debug')
    log_pri_default = 7

    if get_option('buildtype') == 'debug'
        build_stype = 'd'
        add_project_arguments(
            '-DDEBUG_RCU',
            '-fstack-protector-all',
            language: 'c',
        )
    elif get_option('buildtype') == 'debugoptimized'
        build_stype = 'o'
    endif

    add_project_arguments(
        '-DHSE_BUILD_DEBUG',
        language: 'c',
    )
endif

add_project_arguments(
    '-D_LGPL_SOURCE',
    '-Wlogical-op',
    '-Wno-missing-field-initializers',
    '-Wmaybe-uninitialized',
    '-Wno-sign-compare',
    '-Wno-unused-parameter',
    '-Wno-clobbered', # TODO: figure out a way to get back to compiling with -Wclobbered (enabled by -Wextra)
    '-DHSE_LOG_PRI_DEFAULT=@0@'.format(log_pri_default),
    language: 'c',
)

if get_option('debug')
    add_project_arguments(
        '-DWITH_INVARIANTS',
        language: 'c'
    )
endif

build_rtype = build_stype
build_number_result = run_command(
    'sh',
    '-c',
    '[ -n "$BUILD_NUMBER" ]'
)
in_ci = build_number_result.returncode() == 0
if in_ci
    build_number = build_number_result.stdout().strip()
    build_rtype += build_number
endif

libcurl_dep = dependency(
    'libcurl',
    version: '>=7.58.0',
    required: true,
    fallback: ['curl', 'libcurl_dep'],
    default_options: [
        'default_library=static',
        'warning_level=0',
        'werror=false',
    ],
)
libyaml_dep = dependency(
    'yaml-0.1',
    version: '>=0.1.7',
    required: true,
    fallback: ['libyaml', 'libyaml_dep'],
    default_options: [
        'default_library=static',
        'warning_level=0',
        'werror=false',
    ],
)
thread_dep = dependency('threads', required: true)
liburcu_bp_dep = dependency(
    'liburcu-bp',
    version: '>=0.10.1',
    required: true,
    fallback: ['userspace-rcu', 'liburcu_bp_dep'],
    default_options: [
        'default_library=shared',
        'warning_level=0',
        'werror=false',
    ],
)
libbsd_dep = dependency(
    'libbsd',
    version: '>=0.9.0',
    required: true,
    fallback: ['libbsd', 'libbsd_dep'],
    default_options: [
        'default_library=static',
        'warning_level=0',
        'werror=false',
    ],
)
lz4_dep = dependency(
    'liblz4',
    version: '>=1.9.2',
    fallback: ['lz4', 'lz4_dep'],
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
    required: true,
    fallback: ['cjson', 'libcjson_dep'],
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
    required: true,
    fallback: ['libmicrohttpd', 'libmicrohttpd_dep'],
    default_options: [
        'default_library=shared',
        'warning_level=0',
        'werror=false',
    ],
)
m_dep = cc.find_library('m', required: true)
if get_option('tools')
    ncurses_dep = dependency('ncurses', required: true)
    HdrHistogram_c_dep = cc.find_library('hdr_histogram', required: false, disabler: true)
    if (not HdrHistogram_c_dep.found()
            or (HdrHistogram_c_dep.found() and not cc.has_header_symbol(
                'hdr/hdr_histogram.h',
                'hdr_record_value_atomic',
                dependencies: [HdrHistogram_c_dep]))
            or get_option('wrap_mode') == 'forcefallback'
            or 'HdrHistogram_c' in get_option('force_fallback_for'))
        HdrHistogram_c_options = cmake.subproject_options()
        HdrHistogram_c_options.add_cmake_defines({
            'HDR_HISTOGRAM_BUILD_SHARED': false,
            'HDR_HISTOGRAM_BUILD_PROGRAMS': false,
            'HDR_HISTOGRAM_BUILD_STATIC': true,
        })
        HdrHistogram_c_options.set_override_option('werror', 'false')
        HdrHistogram_c_options.set_override_option('warning_level', '0')
        HdrHistogram_c_proj = cmake.subproject('HdrHistogram_c', options: HdrHistogram_c_options)
        HdrHistogram_c_dep = HdrHistogram_c_proj.dependency('hdr_histogram_static')
        HdrHistogram_c_from_subproject = true
    else
        HdrHistogram_c_from_subproject = false
    endif
    libmongoc_dep = dependency('libmongoc-1.0', version: '>=1.7.3', required: false, disabler: true)
    libbson_dep = dependency('libbson-1.0', version: '>=1.7.3', required: false, disabler: true)
    mongo_c_driver_force_fallback = get_option('wrap_mode') == 'forcefallback' or 'mongo-c-driver' in get_option('force_fallback_for')
    if not libmongoc_dep.found() or not libbson_dep.found() or mongo_c_driver_force_fallback
        mongo_c_driver_options = cmake.subproject_options()
        mongo_c_driver_options.add_cmake_defines({
            'ENABLE_TESTS': false,
            'ENABLE_EXAMPLES': false,
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
                # Have to link against libresolv for static libmongoc
                cc.find_library('resolv', required: true),
            ]
        endif
        if not libbson_dep.found() or mongo_c_driver_force_fallback
            libbson_dep = mongo_c_driver_proj.dependency('bson_static')
        endif
    endif
else
    ncurses_dep = disabler()
    HdrHistogram_c_dep = disabler()
    libmongoc_dep = disabler()
    libbson_dep = disabler()
endif

bindings = []
if 'all' in get_option('bindings')
    assert(get_option('bindings').length() == 1, 'The -Dbindings=all option cannot have additional values')
    bindings += 'python'
elif 'none' in get_option('bindings')
    assert(get_option('bindings').length() == 1, 'The -Dtests=bindings option cannot have additional values')
else
    foreach b : get_option('bindings')
        bindings += b
    endforeach
endif

# Add paths to these variables if you want to see targets in the runtime
# environment
executable_paths = []
library_paths = []

if get_option('tests')
    find_program(
        'gawk',
        required: true,
    )
    mapi_idx_generate = find_program(
        'scripts' / 'build' / 'mapi_idx_generate',
        required: true,
    )
    ut_mock_decl_files = find_program(
        'scripts' / 'build' / 'ut_mock_decl_files',
        required: true,
    )
    utpp = find_program(
        'scripts' / 'build' / 'utpp',
        required: true,
    )
endif

exe_install_rpath = get_option('install-rpath') ? '$ORIGIN' / '..' / get_option('libdir') : ''

subdir('config')
subdir('3rdparty')
subdir('include')
if get_option('tests') or get_option('tools')
    # need access to tools_includes for unit tests and tools
    subdir('tools' / 'include')
endif
if get_option('tests')
    # need to know about mocks, framework, test support sources before entering lib directory
    subdir('tests' / 'mocks')
    subdir('tests' / 'support')
    subdir('tests' / 'framework')
endif
subdir('lib')
subdir('cli')
subdir('samples')
if get_option('ycsb')
    subdir('hsejni')
endif
if get_option('docs')
    subdir('docs')
endif

# Environment in which various run_targets and tests will run in
run_env = environment()

if 'python' in bindings
    hse_python = subproject(
        'hse-python',
        required: true,
        default_options: [
            'experimental=@0@'.format(get_option('experimental')),
            'tests=@0@'.format(get_option('tests')),
        ],
    )

    hse_python_depends = [
        hse_python.get_variable('extension_modules'),
    ]
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

if get_option('db_bench')
    subproject('db_bench')
    executable_paths += meson.project_build_root() / 'subprojects/db_bench'
endif

subdir('tools')

run_env.append('PATH', executable_paths)

if get_option('tests')
    # now that we have libhse-mock, go into repository directory
    subdir('tests' / 'mocks' / 'repository')
    subdir('tests')
endif

format = find_program('scripts' / 'dev' / 'format', required: true)
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
    if fs.exists(meson.project_source_root() / '.git')
        run_target(
            'git-hooks',
            command: [
                find_program('scripts' / 'git-hooks' / 'link'),
            ],
        )
    endif

    meson.add_dist_script('scripts' / 'release' / 'gen-version')
endif

checkoss = find_program('scripts' / 'dev' / 'checkoss')
run_target(
    'checkoss',
    command: [
        checkoss,
        '@BUILD_ROOT@',
        '@SOURCE_ROOT@',
    ],
)

gcovr = find_program('gcovr', required: get_option('b_coverage'))
if gcovr.found() and get_option('b_coverage') and get_option('tests')
    reports = {
        'text': [ '-o' ],
        'html': [ '--html', '--html-details', '-o' ],
        'json': [ '--json-pretty', '-o' ],
        'xml': [ '--sonarqube' ],
    }

    foreach type, args : reports
        custom_target(
            'gcovr-@0@'.format(type),
            command: [
                'gcovr',
                '-r',
                '@SOURCE_ROOT@',
                '@BUILD_ROOT@' / 'lib',
                args,
                '@OUTPUT@',
                '-f',
                '@SOURCE_ROOT@' / 'lib'
            ],
            depends: unit_test_exes,
            output: 'coverage.@0@'.format(type)
        )
    endforeach
endif
