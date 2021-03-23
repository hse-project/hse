hsejni_parse_test = executable(
	'hsejni_parse_test',
	['hsejni_parse_test.c'],
	c_args: [
		'-DHSE_MOCKING=1',
		'-DCOMPNAME="hsejni"',
	],
	include_directories: [
		hse_include_directories,
		public_mock_includes,
		test_support_includes,
	],
	dependencies: [
		hse_mock_dep,
	],
)

test(
	'hsejni_parse_test',
	hsejni_parse_test,
	suite: ['unit', 'hsejni'],
)
