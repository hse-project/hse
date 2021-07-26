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
    'lc': {
        'lc_test': {},
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
        'csched_test': {
            'c_args': [ '-DHSE_EXPERIMENTAL' ],
        },
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
    'config': {
        'argv_test': {},
        'config_test': {
            'args': [
                meson.current_source_dir() / 'config',
            ],
        },
        'runtime_home_test': {},
    },
    'framework': {
        'mock_test': {},
    },
    'kvdb': {
        'ctxn_perfc_test': {},
        'ikvdb_test': {},
        'kvdb_ctxn_test': {},
        'kvdb_keylock_test': {},
        'kvdb_home_test': {},
        'kvdb_log_test': {
            'args': [
                meson.current_source_dir() / 'cn' / 'mdc_images',
            ],
        },
        'kvdb_rest_test': {},
        'kvdb_health_test': {},
        'mclass_policy_test': {},
        'sched_sts_test': {
            'cases': {
                'default': [],
                'debug': ['debug'],
            },
        },
        'throttle_test': {},
        'viewset_test': {},
    },
    'mpool': {
        'mpool_test': {
            'sources': [
                files('mpool' / 'common.c'),
            ],
            'include_directories': [
                mpool_internal_includes,
            ],
            'args': [
                '--home',
                tests_dir / 'mpool_test',
            ],
            'requires_home': true,
        },
        'mblock_test': {
            'sources': [
                files('mpool' / 'common.c'),
            ],
            'include_directories': [
                mpool_internal_includes,
            ],
            'args': [
                '--home',
                tests_dir / 'mblock_test',
            ],
            'requires_home': true,
        },
        'mdc_test': {
            'sources': [
                files('mpool' / 'common.c'),
            ],
            'include_directories': [
                mpool_internal_includes,
            ],
            'args': [
                '--home',
                tests_dir / 'mdc_test',
            ],
            'requires_home': true,
        },
        'mcache_test': {
            'sources': [
                files('mpool' / 'common.c'),
            ],
            'include_directories': [
                mpool_internal_includes,
            ],
            'args': [
                '--home',
                tests_dir / 'mcache_test',
            ],
            'requires_home': true,
        },
    },
    'kvs': {},
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
        'bonsai_tree_test': {
            'cases': {
                'cheap': ['-c'],
                'malloc': ['-m'],
            },
         },
        'cheap_test': {
            'sources': [
                files(
                    'util' / 'cheap_testlib.c',
                ),
            ],
        },
        'compression_test': {},
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
        'parse_num_test': {},
        'perfc_test': {},
        'printbuf_test': {},
        'program_name_test': {},
        'rbtree_test': {},
        'rest_api_test': {},
        'rest_client_test': {
            'args': [
                '--home',
                tests_dir / 'rest_client_test',
            ],
            'requires_home': true,
        },
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

unit_test_exes = []
foreach c, tests : components
    foreach t, params : tests
        if params.get('requires_home', false)
            home_dir = tests_dir / t
            if not fs.exists(home_dir)
                run_command(
                    'mkdir',
                    home_dir,
                    check: true,
                )
            endif
        endif

        t_exe = executable(
            t,
            [
                '../framework/src/fixtures.c',
                c / '@0@.c'.format(t),
                params.get('sources', []),
            ],
            c_args: [
                '-DCOMPNAME="kvdb"',
                '-D_GNU_SOURCE=1',
                params.get('c_args', []),
            ],
            include_directories: params.get('include_directories', []),
            dependencies: [
                hse_mock_dep,
                hse_mock_repository_dep,
                hse_dependencies,
                params.get('dependencies', []),
            ],
            gnu_symbol_visibility: 'hidden',
        )
        unit_test_exes += t_exe

        if 'cases' in params
            foreach ident, args : params['cases']
                t_name = ident == 'default' ? t : '@0@[@1@]'.format(t, ident)

                test(
                    t_name,
                    t_exe,
                    args: args,
                    env: params.get('env', environment()),
                    is_parallel: params.get('is_parallel', true),
                    suite: ['unit', c] + params.get('suites', []),
                    timeout: 300,
                )
            endforeach
        else
            test(
                t,
                t_exe,
                args: params.get('args', []),
                env: params.get('env', environment()),
                is_parallel: params.get('is_parallel', true),
                suite: ['unit', c] + params.get('suites', []),
                timeout: 300,
            )
        endif
    endforeach
endforeach
