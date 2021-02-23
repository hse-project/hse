mock_repository_sources = [
	files(
		'mock_c0cn.c',
		'mock_kbb_vbb.c',
		'mock_kvset_builder.c',
		'mock_kvset.c',
		'mock_log.c',
		'mock_mpool.c',
	),
	mapi_idx_h,
]

mock_repository_includes = include_directories('.')

hse_mock_repository = shared_library(
	'hse-mock-repository',
	mock_repository_sources,
	c_args: [
		'-DHSE_UNIT_TEST_MODE=1',
		'-DCOMPNAME="kvdb"',
		'-DXXH_PRIVATE_API',
	],
	include_directories: [
		hse_include_directories,
		hse_mock_include_directories,
		component_root_includes,
	],
	dependencies: [
		hse_mock_dep,
		hse_dependencies,
	],
)

hse_mock_repository_dep = declare_dependency(
	link_with: hse_mock_repository,
	include_directories: [
		mock_repository_includes,
	],
)
