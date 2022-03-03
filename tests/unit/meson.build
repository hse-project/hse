components = {
    'c0': {
        'c0_kvmultiset_test': {},
        'c0_kvset_iterator_test': {},
        'c0_kvset_test': {
            'c_args': cc.get_supported_arguments(['-Wno-clobbered']),
        },
        'c0_test': {
            'sources': [
                files(
                    'c0/cn_mock.c',
                    'c0/c0sk_mock.c',
                ),
            ],
        },
        'c0sk_test': {
            'sources': [
                files(
                    'c0/cn_mock.c',
                    meson.project_source_root() / 'tools/key_generation.c',
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
                meson.current_source_dir() / 'cn/mblock_images',
            ],
        },
        'cn_api_test': {},
        'cn_cursor_test': {},
        'cndb_log_test': {
            'args': [
                meson.current_source_dir() / 'cn/mdc_images',
            ]
        },
        'cndb_test': {},
        'cn_ingest_test': {},
        'cn_logging_test': {},
        'cn_make_test': {},
        'cn_mblock_test': {},
        'cn_open_test': {},
        'cn_perfc_test': {},
        'cn_tree_test': {},
        'csched_sp3_test': {
            # mapi_malloc_tester isn't reliable in multithreaded environments. Add to
            # non-deterministic suite
            'suites': ['non-deterministic'],
            'cases': {
                'default': [],
                'debug': ['debug'],
            },
        },
        'kblock_builder_test': {},
        'kblock_reader_test': {},
        'kcompact_test': {},
        'kvset_builder_test': {},
        'mbset_test': {},
        'merge_test': {
            'args': [
                meson.current_source_dir() / 'cn/merge-test-cases',
            ],
        },
        'vblock_builder_test': {},
        'vblock_reader_test': {},
        'wbt_iterator_test': {
            'args': [
                meson.current_source_dir() / 'cn/mblock_images',
            ],
        },
        'wbt_reader_test': {
            'args': [
                meson.current_source_dir() / 'cn/mblock_images',
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
        'hse_gparams_test': {},
        'param_test': {},
    },
    'kvdb': {
        'ikvdb_test': {},
        'kvdb_cparams_test': {},
        'kvdb_ctxn_test': {},
        'kvdb_keylock_test': {},
        'kvdb_health_test': {},
        'kvdb_home_test': {},
        'kvdb_meta_test': {
            'args': [
                meson.current_source_dir() / 'kvdb/kvdb-meta-files',
            ],
        },
        'kvdb_rest_test': {},
        'kvdb_rparams_test': {},
        'mclass_policy_test': {},
        'omf_version_test': {},
        'throttle_test': {},
        'viewset_test': {},
        'kvdb_pfxlock_test': {},
        'kvdb_ctxn_pfxlock_test': {},
    },
    'mpool': {
        'mpool_test': {
            'sources': [
                files('mpool/common.c'),
            ],
            'include_directories': [
                mpool_internal_includes,
            ],
        },
        'mblock_test': {
            'sources': [
                files('mpool/common.c'),
            ],
            'include_directories': [
                mpool_internal_includes,
            ],
        },
        'mdc_test': {
            'sources': [
                files('mpool/common.c'),
            ],
            'include_directories': [
                mpool_internal_includes,
            ],
        },
        'mcache_test': {
            'sources': [
                files('mpool/common.c'),
            ],
            'include_directories': [
                mpool_internal_includes,
            ],
        },
    },
    'kvs': {
        'kvs_cparams_test': {},
        'kvs_cursor_test': {},
        'kvs_rparams_test': {},
    },
    'util': {
        'allocation_test': {},
        'atomic_test': {
            'sources': [
                files(
                    'util/multithreaded_tester.c',
                ),
            ],
        },
        'bin_heap_test': {
            'sources': [
                files(
                    'util/sample_element_source.c',
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
                    'util/cheap_testlib.c',
                ),
            ],
        },
        'compression_test': {},
        'data_tree_test': {
            'sources': [
                files(
                    'util/multithreaded_tester.c',
                ),
            ],
        },
        'element_source_test': {
            'sources': [
                files(
                    'util/sample_element_source.c',
                ),
            ],
        },
        'event_counter_test': {},
        'event_timer_test': {},
        'fmt_test': {},
        'hash_test': {},
        'hlog_unit_test': {},
        # This test requires access to some private information, so we compile it
        # in with hse_err.c.
        'hse_err_test': {},
        'json_test': {},
        'keycmp_test': {},
        'keylock_test': {},
        'key_util_test': {},
        'list_test': {},
        'log2_test': {},
        'logging_test': {},
        'parse_num_test': {},
        'perfc_test': {},
        'printbuf_test': {},
        'rbtree_test': {},
        'rest_api_test': {},
        'rest_client_test': {},
        'seqno_test': {
            'c_args': cc.get_supported_arguments(['-Wno-clobbered']),
        },
        'spinlock_test': {
            'sources': [
                files(
                    'util/thread_tester.c',
                ),
            ],
        },
        'structured_logging_test': {},
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
        t_exe = executable(
            t,
            [
                c / '@0@.c'.format(t),
                params.get('sources', []),
            ],
            c_args: params.get('c_args', []),
            include_directories: params.get('include_directories', []),
            dependencies: [
                hse_mock_dep,
                hse_mock_repository_dep,
                hse_dependencies,
                hse_test_framework_dep,
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
