util_test_common_includes = []

util_test_common_sources = []

util_test_common_dependencies = []

util_tests = {
	'allocation_test': {},
	'atomic_test': {
		'sources': [
			files(
				'multithreaded_tester.c',
			),
		],
		'dependencies': [
			pthread_dep,
		],
	},
	'bin_heap_test': {
		'sources': [
			files(
				'sample_element_source.c',
			),
		],
	},
	'bloom_filter_test': {
		'env': {
			'MALLOC_PERTURB_': '0',
		},
	},
	'bonsai_tree_test': {
		'dependencies': [
			pthread_dep,
			liburcu_bp_dep,
		],
	},
	'cheap_test': {
		'sources': [
			files(
				'cheap_testlib.c',
			),
		],
	},
	'compression_test': {},
	'config_test': {},
	'darray_test': {},
	'data_tree_test': {
		'sources': [
			files(
				'multithreaded_tester.c',
			),
		],
		'dependencies': [
			pthread_dep,
		],
	},
	'delay_test': {},
	'element_source_test': {
		'sources': [
			files(
				'sample_element_source.c',
			),
		],
	},
	'event_counter_test': {},
	'event_timer_test': {
		'dependencies': [
			pthread_dep,
		],
	},
	'fmt_test': {},
	'hash_test': {},
	'hlog_unit_test': {},
	# This test requires access to some private information, so we compile it
	# in with hse_err.c. It also necessitates mpool as a dependency.
	'hse_err_test': {
		'sources': files(
			meson.project_source_root() / 'lib' / 'util' / 'src' / 'hse_err.c',
		),
		'dependencies': [
			mpool_dep,
		],
	},
	'json_test': {},
	'keycmp_test': {},
	'keylock_test': {},
	'key_util_test': {},
	'list_test': {},
	'log2_test': {},
	# REVISIT: logging_test test periodically fails because the
	# because the syslog/vsyslog functions underlying hse_xlog() are
	# intercepted to save log messages into a shared buffer. But
	# there are multiple threads that use syslog/vsyslog, so by the
	# time this message is parsed by process_json_payload(), the
	# buffer could have been reused.
	# 'logging_test': {},
	'mtx_pool_test': {
		'dependencies': [
			pthread_dep,
		],
	},
	'param_test': {},
	'parse_num_test': {},
	'parser_test': {},
	'perfc_test': {},
	'printbuf_test': {},
	'program_name_test': {},
	'rbtree_test': {},
	'rest_api_test': {
		'dependencies': [
			libcurl_dep,
			pthread_dep,
		],
	},
	'rest_client_test': {
		'dependencies': [
			libcurl_dep,
			libbsd_dep,
		],
	},
	'rwsem_test': {
		'sources': [
			files(
				'multithreaded_tester.c',
			),
		],
		'dependencies': [
			pthread_dep,
		],
	},
	'seqno_test': {},
	'spinlock_test': {
		'sources': [
			files(
				'thread_tester.c',
			),
		],
		'dependencies': [
			pthread_dep,
		],
	},
	# REVISIT: structured_logging_test test periodically fails because the
	# because the syslog/vsyslog functions underlying hse_xlog() are
	# intercepted to save log messages into a shared buffer. But
	# there are multiple threads that use syslog/vsyslog, so by the
	# time this message is parsed by process_json_payload(), the
	# buffer could have been reused.
	# 'structured_logging_test': {},
	'table_test': {},
	'timer_test': {},
	'token_bucket_test': {},
	'vlb_test': {},
	'workqueue_test': {
		'dependencies': [
			pthread_dep,
		],
	},
	'xrand_test': {
		'dependencies': [
			pthread_dep,
		],
	},
	'yaml_test': {},
}

foreach t, params : util_tests
	t_sources = common_test_sources
	t_sources += util_test_common_sources
	t_sources += '@0@.c'.format(t)
	if 'sources' in params
		t_sources += params['sources']
	endif

	t_c_args = common_test_c_args
	if 'c_args' in params
		t_c_args += params['c_args']
	endif

	t_include_directories = common_test_includes
	t_include_directories += util_test_common_includes
	if 'include_directories' in params
		t_include_directories += params['include_directories']
	endif

	t_dependencies = common_test_dependencies
	t_dependencies += util_test_common_dependencies
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

	t_suites = ['unit', 'util']
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
