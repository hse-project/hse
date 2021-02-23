common_test_c_args = [
	'-DHSE_UNIT_TEST_MODE=1',
	'-DCOMPNAME="kvdb"',
	'-DXXH_PRIVATE_API',
]

common_test_includes = [
	hse_include_directories,
	hse_mock_include_directories,
]

common_test_sources = []

common_test_dependencies = [
	hse_mock_dep,
	hse_mock_repository_dep,
	hse_dependencies,
]

subdir('c0')
subdir('cn')
subdir('framework')
subdir('kvdb')
subdir('kvs')
subdir('util')
