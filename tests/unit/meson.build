common_test_c_args = [
	'-DHSE_UNIT_TEST_MODE=1',
	'-DCOMPNAME="kvdb"',
	'-DXXH_PRIVATE_API',
]

common_test_includes = []

common_test_sources = []

common_test_dependencies = [
	hse_mock_dep,
	hse_mock_repository_dep,
	hse_dependencies,
]

components = {
	'c0': {
		'c0_kvmultiset_test': {},
		'c0_kvset_iterator_test': {},
		'c0_kvset_test': {},
		'c0_test': {
			'sources': [
				files(
					'c0' / 'cn_mock.c',
					'c0' / 'c0sk_mock.c',
				),
			],
		},
		'c0sk_test': {
			'sources': [
				files(
					'c0' / 'cn_mock.c',
					meson.project_source_root() / 'tools' / 'key_generation.c',
				),
			],
		},
	},
	'cn': {
		'blk_list_test': {},
		'bloom_reader_test': {
			'args': [
				meson.current_source_dir() / 'cn' / 'mblock_images',
			],
		},
		'cn_api_test': {},
		'cn_cursor_test': {},
		'cndb_log_test': {
			'args': [
				meson.current_source_dir() / 'cn' / 'mdc_images',
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
				meson.current_source_dir() / 'cn' / 'merge-test-cases',
			],
		},
		'vblock_builder_test': {},
		'vblock_reader_test': {},
		'wbt_iterator_test': {
			'args': [
				meson.current_source_dir() / 'cn' / 'mblock_images',
			],
		},
		'wbt_reader_test': {
			'args': [
				meson.current_source_dir() / 'cn' / 'mblock_images',
			],
		},
		'wbt_test': {},
	},
	'framework': {
		'smoke': {},
	},
	'kvdb': {
		'ctxn_perfc_test': {},
		'hse_params_test': {},
		'ikvdb_test': {},
		'kvdb_cparams_test': {},
		'kvdb_ctxn_test': {},
		'kvdb_keylock_test': {},
		'kvdb_log_test': {
			'args': [
				meson.current_source_dir() / 'cn' / 'mdc_images',
			],
		},
		'kvdb_rest_test': {},
		'kvdb_rparams_test': {},
		'kvdb_test': {},
		'mclass_policy_test': {},
		'sched_sts_test': {
			'cases': {
				'default': [],
				'debug': ['debug'],
			},
		},
		'throttle_test': {},
		'wp_test': {
			'args': [
				meson.project_source_root() / 'config',
			],
		},
	},
	'kvs': {
		'kvs_cparams_test': {},
		'kvs_rparams_test': {},
	},
	'util': {
		'allocation_test': {},
		'atomic_test': {
			'sources': [
				files(
					'util' / 'multithreaded_tester.c',
				),
			],
		},
		'bin_heap_test': {
			'sources': [
				files(
					'util' / 'sample_element_source.c',
				),
			],
		},
		'bloom_filter_test': {
			'env': {
				'MALLOC_PERTURB_': '0',
			},
		},
		'bonsai_tree_test': {},
		'cheap_test': {
			'sources': [
				files(
					'util' / 'cheap_testlib.c',
				),
			],
		},
		'compression_test': {},
		'config_test': {},
		'darray_test': {},
		'data_tree_test': {
			'sources': [
				files(
					'util' / 'multithreaded_tester.c',
				),
			],
		},
		'delay_test': {},
		'element_source_test': {
			'sources': [
				files(
					'util' / 'sample_element_source.c',
				),
			],
		},
		'event_counter_test': {},
		'event_timer_test': {},
		'fmt_test': {},
		'hash_test': {},
		'hlog_unit_test': {},
		# This test requires access to some private information, so we compile it
		# in with hse_err.c. It also necessitates mpool as a dependency.
		'hse_err_test': {
			'sources': files(
				meson.project_source_root() / 'lib' / 'util' / 'src' / 'hse_err.c',
			),
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
		'mtx_pool_test': {},
		'param_test': {},
		'parse_num_test': {},
		'parser_test': {},
		'perfc_test': {},
		'printbuf_test': {},
		'program_name_test': {},
		'rbtree_test': {},
		'rest_api_test': {},
		'rest_client_test': {},
		'rwsem_test': {
			'sources': [
				files(
					'util' / 'multithreaded_tester.c',
				),
			],
		},
		'seqno_test': {},
		'spinlock_test': {
			'sources': [
				files(
					'util' / 'thread_tester.c',
				),
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
		'workqueue_test': {},
		'xrand_test': {},
		'yaml_test': {},
	},
}

foreach c, tests : components
	foreach t, params : tests
		t_sources = common_test_sources
		t_sources += c / '@0@.c'.format(t)
		if 'sources' in params
			t_sources += params['sources']
		endif

		t_c_args = common_test_c_args
		if 'c_args' in params
			t_c_args += params['c_args']
		endif

		t_include_directories = common_test_includes
		if 'include_directories' in params
			t_include_directories += params['include_directories']
		endif

		t_dependencies = common_test_dependencies
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

		t_suites = ['unit', c]
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
endforeach
