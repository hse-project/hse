smoke = executable(
	'smoke',
	[
		'smoke.c',
		common_test_sources,
	],
	c_args: common_test_c_args,
	include_directories: common_test_includes,
	dependencies: [
		hse_mock_dep,
	],
)

test(
	'smoke',
	smoke,
	suite: ['unit', 'framework'],
)
