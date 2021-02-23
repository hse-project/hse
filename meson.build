project(
	'hse',
	['c', 'java'],
	version: '1.10.0',
	license: [
		'Apache-2.0',
	],
	default_options: [
		'c_std=gnu99',
		'buildtype=debugoptimized',
		'warning_level=2',
	],
	meson_version: '>=0.57.0',
)

pkg = import('pkgconfig')
fs = import('fs')
cmake = import('cmake')
pymod = import('python')

cc = meson.get_compiler('c')
javac = meson.get_compiler('java')

version_components = meson.project_version().split('.')

hse_major_version = version_components[0]
hse_minor_version = version_components[1]
hse_patch_version = version_components[2]

git = find_program('git')
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
	version_file_components = run_command(
		'cat',
		meson.project_source_root() / 'VERSION',
		check: true,
	).stdout().strip().split('\n')

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
elif get_option('buildtype').startswith('debug')
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
	'-Wlogical-op',
	'-Wno-missing-field-initializers',
	'-Wmaybe-uninitialized',
	'-Wno-sign-compare',
	'-Wno-unused-parameter',
	'-Wno-clobbered', # TODO: figure out a way to get back to compiling with -Wclobbered (enabled by -Wextra)
	'-DHSE_LOG_PRI_DEFAULT=@0@'.format(log_pri_default),
	language: 'c',
)

build_rtype = ''
build_number_result = run_command(
	'sh',
	'-c',
	'[ -n "$BUILD_NUMBER" ]'
)
in_ci = build_number_result.returncode() == 0
if in_ci
	build_number = build_number_result.stdout().strip()
	build_rtype = '@0@@1@'.format(build_stype, build_number)
endif

# remove this libcurl funny business if Meson supports 'fallback' for CMake subprojects
libcurl_dep = dependency(
	'libcurl',
	version: '>=7.61.1',
	required: true,
	fallback: ['curl', 'libcurl_dep'],
)
libyaml_dep = dependency(
	'yaml-0.1',
	version: '>=0.1.7',
	required: true,
	fallback: ['libyaml', 'libyaml_dep']
)
pthread_dep = cc.find_library('pthread', required: true)
uuid_dep = dependency('uuid', version: '>=2.31.1', required: true)
liburcu_bp_dep = dependency(
	'liburcu-bp',
	version: '>=0.10.1',
	required: true,
	fallback: ['userspace-rcu', 'liburcu_bp_dep'],
)
cJSON_dep = dependency(
	'libcjson',
	version: '1.7.14',
	required: get_option('wrap_mode') == 'nofallback',
)
if (not cJSON_dep.found()
		or get_option('wrap_mode') == 'forcefallback'
		or 'cJSON' in get_option('force_fallback_for'))
	cJSON_options = cmake.subproject_options()
	cJSON_options.add_cmake_defines({
		'BUILD_SHARED_LIBS': get_option('default_library') != 'static',
		'BUILD_SHARED_AND_STATIC_LIBS': get_option('default_library') == 'both',
	})
	cJSON_proj = cmake.subproject('cJSON', options: cJSON_options)
	cJSON_dep = cJSON_proj.dependency('cjson')
	cJSON_from_subproject = true
else
	cJSON_from_subproject = false
endif
libbsd_dep = dependency(
	'libbsd',
	version: '>=0.9.1',
	required: true,
	fallback: ['libbsd', 'libbsd_dep'],
)
lz4_dep = dependency(
	'liblz4',
	version: '==1.9.2',
	required: true,
	fallback: ['lz4', 'lz4_dep'],
)
xxhash_dep = dependency(
	'libxxhash',
	version: '==0.8.0',
	required: true,
	fallback: ['xxhash', 'xxhash_dep'],
)
if get_option('mpool-lib-dir') == ''
	mpool_dep = cc.find_library('mpool', required: true)
else
	mpool_dep = cc.find_library(
		'mpool',
		required: true,
		dirs: get_option('mpool-lib-dir'),
	)
endif
libmicrohttpd_dep = dependency(
	'libmicrohttpd',
	version: '>=0.9.59',
	required: true,
	fallback: ['libmicrohttpd', 'libmicrohttpd_dep'],
)
m_dep = cc.find_library('m', required: true)
valgrind_dep = dependency('valgrind', required: get_option('valgrind-support'))
if get_option('tools')
	ncurses_dep = dependency('ncurses', required: true)
	HdrHistogram_c_dep = cc.find_library('hdr_histogram', required: false)
	HdrHistogram_c_correct_version = false
	if HdrHistogram_c_dep.found()
		HdrHistogram_c_correct_version = cc.compiles(
			'''
			#include <stdbool.h>
			#include <hdr/hdr_histogram.h>

			int
			main(void)
			{
				struct hdr_histogram* histogram;
				bool x = hdr_record_value_atomic(histogram, 0);
				return 0;
			}
			''',
			args: [
				'-Werror',
			],
			dependencies: [
				HdrHistogram_c_dep,
			],
		)
	endif
	if (not HdrHistogram_c_dep.found()
			or (HdrHistogram_c_dep.found() and not HdrHistogram_c_correct_version)
			or get_option('wrap_mode') == 'forcefallback'
			or 'HdrHistogram_c' in get_option('force_fallback_for'))
		HdrHistogram_c_options = cmake.subproject_options()
		HdrHistogram_c_options.add_cmake_defines({
			'HDR_HISTOGRAM_BUILD_SHARED': get_option('default_library') != 'static',
			'HDR_HISTOGRAM_BUILD_PROGRAMS': false,
			'HDR_HISTOGRAM_BUILD_STATIC': get_option('default_library') == 'static',
		})
		HdrHistogram_c_proj = cmake.subproject('HdrHistogram_c', options: HdrHistogram_c_options)
		HdrHistogram_c_dep = HdrHistogram_c_proj.dependency('hdr_histogram@0@'.format(get_option('default_library') == 'static' ? '-static' : ''))
		HdrHistogram_c_from_subproject = true
	else
		HdrHistogram_c_from_subproject = false
	endif
	libmongoc_dep = dependency('libmongoc-1.0', required: false)
	libbson_dep = dependency('libbson-1.0', required: false)
	mongo_c_driver_force_fallback = get_option('wrap_mode') == 'forcefallback' or 'mongo-c-driver' in get_option('force_fallback_for')
	if not libmongoc_dep.found() or not libbson_dep.found() or mongo_c_driver_force_fallback
		mongo_c_driver_options = cmake.subproject_options()
		mongo_c_driver_options.add_cmake_defines({
			'ENABLE_TESTS': false,
			'ENABLE_EXAMPLES': false,
			'ENABLE_MONGOC': not libmongoc_dep.found() or mongo_c_driver_force_fallback ? 'ON' : 'OFF',
			'ENABLE_BSON': not libbson_dep.found() or mongo_c_driver_force_fallback ? 'ON' : 'OFF',
			'ENABLE_STATIC': get_option('default_library') == 'static' ? 'ON' : 'OFF',
		})
		mongo_c_driver_proj = cmake.subproject('mongo-c-driver', options: mongo_c_driver_options)
		if not libmongoc_dep.found() or mongo_c_driver_force_fallback
			if get_option('default_library') == 'static'
				libmongoc_dep = mongo_c_driver_proj.dependency('mongoc_static')
			else
				libmongoc_dep = mongo_c_driver_proj.dependency('mongoc_shared')
			endif
		endif
		if not libbson_dep.found() or mongo_c_driver_force_fallback
			if get_option('default_library') == 'static'
				libbson_dep = mongo_c_driver_proj.dependency('bson_static')
			else
				libbson_dep = mongo_c_driver_proj.dependency('bson_shared')
			endif
		endif
	endif
endif

if not valgrind_dep.found()
	add_project_arguments(
		'-DNVALGRIND',
		language: 'c',
	)
endif

if get_option('tests')
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

exe_install_rpath = get_option('exe-install-rpath') ? '$ORIGIN' / '..' / get_option('libdir') : ''

subdir('config')
subdir('3rdparty')
subdir('include')
if get_option('tests') or get_option('tools')
	# need access to tools_includes for tests and tools
	subdir('tools' / 'include')
endif
if get_option('tests')
	# need to know about mocks, framework, test support sources before entering src directory
	subdir('tests' / 'mocks')
	subdir('tests' / 'framework')
	subdir('tests' / 'support')
endif
subdir('lib')
if get_option('cli')
	subdir('cli')
endif
if get_option('samples')
	subdir('samples')
endif
if get_option('ycsb')
	subdir('hsejni')
endif

if not meson.is_subproject()
	meson.override_dependency('@0@-1'.format(meson.project_name()), hse_dep)
endif

if get_option('bindings-python') or get_option('tools') or get_option('tests')
	python = pymod.find_installation(
		'python3',
		required: true,
	)

	python_has_hse = run_command(
		python,
		'-c',
		'import hse',
	).returncode() == 0

	python_depends = [hse]
	python_env = environment()

	# Use system hse unless nofallback is specified
	if not python_has_hse or get_option('wrap_mode') != 'nofallback'
		hse_python = subproject(
			'hse-python',
			required: true,
			default_options: [
				'tests=false',
			],
		)

		python_depends += hse_python.get_variable('extension_modules')
		python_env.set('PYTHONPATH', hse_python.get_variable('project_build_root'))
	endif

	run_target(
		'python-repl',
		command: [
			python,
		],
		depends: python_depends,
		env: python_env,
	)
endif

if get_option('tests')
	# now that we have libhse-mock, go into repository directory
	subdir('tests' / 'mocks' / 'repository')
	subdir('tests')
endif
if get_option('tools')
	subdir('tools')
endif

clang_format = find_program('clang-format', required: in_ci)
if clang_format.found()
	project_files = run_command(
		'find',
		meson.project_source_root() / 'cli',
		meson.project_source_root() / 'hsejni',
		meson.project_source_root() / 'include',
		meson.project_source_root() / 'lib',
		meson.project_source_root() / 'samples',
		meson.project_source_root() / 'tests',
		meson.project_source_root() / 'tools',
		'-type',
		'f',
		'(',
		'-name',
		'*.[ch]',
		'-o',
		'-name',
		'*.h.in',
		')',
		'-print',
		check: true,
	).stdout().strip().split('\n')

	clang_format_command = [
		clang_format,
		'--style=file',
	]

	if get_option('werror')
		clang_format_command += '--Werror'
	endif

	if in_ci
		clang_format_command += '--dry-run'
	else
		clang_format_command += '-i'
	endif

	clang_format_command += project_files

	run_target(
		'clang-format',
		command: clang_format_command,
	)
endif

black = find_program('black', required: in_ci)
if black.found()
	black_command = [
		black,
		meson.project_source_root(),
	]

	if in_ci
		black_command += [
			'--check',
			'--diff',
		]
	endif

	run_target(
		'black',
		command: black_command,
	)
endif

if not meson.is_subproject()
	meson.add_dist_script('scripts' / 'release' / 'gen-version')
endif
