cn_test_common_includes = [
	cn_includes,
]

cn_test_common_sources = []

cn_test_common_dependencies = []

cn_tests = {
	'blk_list_test': {},
	'bloom_reader_test': {
		'args': [
			meson.current_source_dir() / 'mblock_images',
		],
	},
	'cn_api_test': {},
	'cn_cursor_test': {},
	'cndb_log_test': {
		'args': [
			meson.current_source_dir() / 'mdc_images',
		]
	},
	'cndb_test': {},
	'cn_ingest_test': {},
	# REVISIT: cn_logging_test test periodically fails because the
	# because the syslog/vsyslog functions underlying hse_xlog() are
	# intercepted to save log messages into a shared buffer. But
	# there are multiple threads that use syslog/vsyslog, so by the
	# time this message is parsed by process_json_payload(), the
	# buffer could have been reused.
	# 'cn_logging_test': {},
	'cn_make_test': {},
	'cn_mblock_test': {},
	'cn_open_test': {},
	'cn_perfc_test': {},
	'cn_tree_test': {},
	'csched_noop_test': {},
	'csched_sp3_test': {
		'cases': {
			'default': [],
			'debug': ['debug'],
		},
	},
	'csched_test': {},
	'kblock_builder_test': {},
	'kblock_reader_test': {},
	'kcompact_test': {},
	'kvset_builder_test': {},
	'mbset_test': {},
	'merge_test': {
		'args': [
			meson.current_source_dir() / 'merge-test-cases',
		],
		'dependencies': [
			libyaml_dep,
		],
	},
	'vblock_builder_test': {},
	'vblock_reader_test': {},
	'wbt_iterator_test': {
		'args': [
			meson.current_source_dir() / 'mblock_images',
		],
	},
	'wbt_reader_test': {
		'args': [
			meson.current_source_dir() / 'mblock_images',
		],
	},
	'wbt_test': {},
}

foreach t, params : cn_tests
	t_sources = common_test_sources
	t_sources += cn_test_common_sources
	t_sources += '@0@.c'.format(t)
	if 'sources' in params
		t_sources += params['sources']
	endif

	t_c_args = common_test_c_args
	if 'c_args' in params
		t_c_args += params['c_args']
	endif

	t_include_directories = common_test_includes
	t_include_directories += cn_test_common_includes
	if 'include_directories' in params
		t_include_directories += params['include_directories']
	endif

	t_dependencies = common_test_dependencies
	t_dependencies += cn_test_common_dependencies
	if 'dependencies' in params
		t_dependencies += params['dependencies']
	endif

	t_exe = executable(
		t,
		t_sources,
		c_args: t_c_args,
		include_directories: t_include_directories,
		dependencies: t_dependencies,
	)

	t_suites = ['unit', 'cn']
	if 'suites' in params
		t_suites += params['suites']
	endif

	t_env = 'env' in params ? environment(params['env']) : environment()

	t_is_parallel = 'is_parallel' in params ? params['is_parallel'] : true

	t_args = []
	if 'cases' in params
		foreach ident, args : params['cases']
			t_name = ident == 'default' ? t : '@0@_@1@'.format(t, ident)
			t_args += args

			test(
				t_name,
				t_exe,
				args: t_args,
				env: t_env,
				is_parallel: t_is_parallel,
				suite: t_suites,
			)
		endforeach
	else
		if 'args' in params
			t_args += params['args']
		endif

		test(
			t,
			t_exe,
			args: t_args,
			env: t_env,
			is_parallel: t_is_parallel,
			suite: t_suites,
		)
	endif
endforeach
