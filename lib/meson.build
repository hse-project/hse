_config_h_data = configuration_data({})

_config_h = configure_file(
	input: '_config.h.in',
	output: '_config.h',
	configuration: _config_h_data,
)

subdir('include')
subdir('binding')
subdir('kvs')
subdir('util')
subdir('c0')
subdir('cn')
subdir('kvdb')

component_root_includes = include_directories('.')

hse_sources = [
	_config_h,
	binding_sources,
	c0_sources,
	cn_sources,
	kvdb_sources,
	kvs_sources,
	util_sources,
]

hse_c_args = [
	'-DCOMPNAME="kvdb"',
	'-DXXH_PRIVATE_API',
	'-fvisibility=hidden',
]

hse_include_directories = [
	ikvdb_includes,
	component_root_includes,
	public_includes,
	third_party_includes,
	util_includes,
]

hse_dependencies = [
	cJSON_dep,
	libbsd_dep,
	libcurl_dep,
	libmicrohttpd_dep,
	liburcu_bp_dep,
	libyaml_dep,
	lz4_dep,
	m_dep,
	mpool_dep,
	pthread_dep,
	rbtree_dep,
	uuid_dep,
]

hse_public_dependencies = [
	uuid_dep,
]

hse = both_libraries(
	'@0@-@1@'.format(meson.project_name(), hse_major_version),
	hse_sources,
	c_args: hse_c_args,
	include_directories: hse_include_directories,
	dependencies: hse_dependencies,
	version: meson.project_version(),
	install: true,
)

hse_dep = declare_dependency(
	link_with: hse,
	version: meson.project_version(),
	sources: [
		version_h,
	],
	include_directories: [
		public_includes,
	],
	dependencies: hse_public_dependencies,
)

hse_static_dep = declare_dependency(
	link_with: hse.get_static_lib(),
	version: meson.project_version(),
	sources: [
		version_h,
	],
	include_directories: [
		public_includes,
	],
	dependencies: hse_public_dependencies,
)

if get_option('tests')
	hse_mock_c_args = [
		'-DCOMPNAME="kvdb"',
		'-DXXH_PRIVATE_API',
		'-DHSE_UNIT_TEST_MODE=1',
		'-fvisibility=default',
	]

	hse_mock_include_directories = [
		test_framework_includes,
		test_support_includes,
		mock_includes,
		tools_includes,
	]

	hse_mock_sources = [
		test_support_sources,
		mock_sources,
	]

	hse_mock = library(
		'@0@-mock-@1@'.format(meson.project_name(), hse_major_version),
		hse_sources + hse_mock_sources,
		c_args: hse_c_args + hse_mock_c_args,
		include_directories: hse_include_directories + hse_mock_include_directories,
		dependencies: hse_dependencies,
		version: meson.project_version(),
	)

	hse_mock_dep = declare_dependency(
		link_with: hse_mock,
		version: meson.project_version(),
		sources: [
			version_h,
			mapi_idx_h,
			mock_sources,
		],
		include_directories: [
			public_includes,
		],
		dependencies: hse_public_dependencies,
	)
endif

pkg.generate(
	hse,
	description: 'Fast key-value storage for SSDs and persistent memory',
	filebase: '@0@-@1@'.format(meson.project_name(), hse_major_version),
	name: meson.project_name(),
	version: meson.project_version(),
	url: 'https://github.com/hse-project/hse',
	requires: hse_public_dependencies,
	subdirs: [
		'@0@-@1@'.format(meson.project_name(), hse_major_version),
	],
)
