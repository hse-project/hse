hsejni_parse_test = executable(
	'hsejni_parse_test',
	['hsejni_parse_test.c'],
	c_args: [
		'-DCOMPNAME="hsejni"',
	],
	include_directories: [
		test_support_includes,
	],
	dependencies: [
		hse_mock_dep,
		hsejni_dep,
		libhse_cli_dep,
		cJSON_dep,
		libbsd_dep,
	],
)

test(
	'hsejni_parse_test',
	hsejni_parse_test,
	suite: ['unit', 'hsejni'],
)
