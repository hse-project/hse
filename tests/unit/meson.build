# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# SPDX-FileCopyrightText: Copyright 2020 Micron Technology, Inc.

components = {
    'c0': {
        'c0_kvmultiset_test': {
            'dependencies': [
                hse_test_support_dep,
            ],
        },
        'c0_kvset_iterator_test': {
            'dependencies': [
                hse_test_support_dep,
            ],
        },
        'c0_kvset_test': {
            'c_args': cc.get_supported_arguments('-Wno-clobbered'),
            'dependencies': [
                hse_test_support_dep,
            ],
        },
        'c0_test': {
            'sources': files(
                'c0/cn_mock.c',
                'c0/c0sk_mock.c',
            ),
            'dependencies': [
                hse_test_support_dep,
            ],
        },
        'c0sk_test': {
            'sources': files(
                'c0/cn_mock.c',
                meson.project_source_root() / 'tools/key_generation.c'
            ),
            'include_directories': [
                tools_includes,
            ],
            'dependencies': [
                hse_test_support_dep,
            ],
        },
    },
    'lc': {
        'lc_test': {},
    },
    'cn': {
        'blk_list_test': {},
        # 'bloom_reader_test': {
        #     'args': [
        #         meson.current_source_dir() / 'cn/mblock_images',
        #     ],
        # },
        'cn_api_test': {},
        'cn_tree_cursor_test': {},
        'cn_ingest_test': {},
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
        'hblock_builder_test': {},
        'hblock_reader_test': {},
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
        'cn_move_test': {},
        'route_test': {},
        'vblock_builder_test': {},
        'vblock_reader_test': {},
        # 'wbt_iterator_test': {
        #     'args': [
        #         meson.current_source_dir() / 'cn/mblock_images',
        #     ],
        # },
        # 'wbt_reader_test': {
        #     'args': [
        #         meson.current_source_dir() / 'cn/mblock_images',
        #     ],
        # },
        'wbt_test': {
            'dependencies': [
                hse_test_support_dep,
            ],
        },
    },
    'cndb': {
        'cndb_test': {},
        'cndb_txn_test': {},
    },
    'config': {
        'config_test': {},
        'hse_gparams_test': {},
        'param_test': {},
    },
    'error': {
        'merr_test': {},
    },
    'kvdb': {
        'ikvdb_test': {
            'dependencies': [
                hse_test_support_dep,
            ],
        },
        'kvdb_cparams_test': {},
        'kvdb_ctxn_pfxlock_test': {},
        'kvdb_ctxn_test': {},
        'kvdb_health_test': {},
        'kvdb_home_test': {
            'args': [
                meson.current_source_dir() / 'kvdb/kvdb-conf-files',
            ],
        },
        'kvdb_keylock_test': {},
        'kvdb_meta_test': {
            'args': [
                meson.current_source_dir() / 'kvdb/kvdb-meta-files',
            ],
        },
        'kvdb_modes_test': {},
        'kvdb_pfxlock_test': {},
        'kvdb_rest_test': {
            'dependencies': [
                cjson_dep,
                hse_cli_dep,
                hse_test_fixtures_dep,
            ],
            'suites': ['rest'],
        },
        'kvdb_rparams_test': {},
        'mclass_policy_test': {},
        'omf_version_test': {},
        'throttle_test': {},
        'viewset_test': {},
    },
    'kvs': {
        'kvs_cparams_test': {},
        'kvs_cursor_test': {},
        'kvs_rest_test': {
            'dependencies': [
                cjson_dep,
                hse_cli_dep,
                hse_test_fixtures_dep,
            ],
            'suites': ['rest'],
        },
        'kvs_rparams_test': {},
    },
    'mpool': {
        'mpool_test': {
            'sources': files('mpool/common.c'),
            'include_directories': [
                mpool_internal_includes,
            ],
        },
        'mblock_test': {
            'sources': files('mpool/common.c'),
            'include_directories': [
                mpool_internal_includes,
            ],
            'dependencies': [
                hse_test_support_dep,
            ],
        },
        'mdc_test': {
            'sources': files('mpool/common.c'),
            'include_directories': [
                mpool_internal_includes,
            ],
            'dependencies': [
                hse_test_support_dep,
            ],
        },
        'mcache_test': {
            'sources': files('mpool/common.c'),
            'include_directories': [
                mpool_internal_includes,
            ],
            'dependencies': [
                hse_test_support_dep,
            ],
        },
    },
    'pidfile': {
        'pidfile_test': {
            'args': [meson.current_source_dir() / 'pidfile'],
        },
    },
    'rest': {
        'global_rest_test': {
            'dependencies': [
                cjson_dep,
                hse_cli_dep,
            ],
        },
        'rest_test': {
            'dependencies': [
                hse_cli_dep,
                hse_rest_dep,
            ]
        },
    },
    'util': {
        'allocation_test': {},
        'atomic_test': {
            'sources': files('util/multithreaded_tester.c'),
        },
        'bin_heap_test': {
            'sources': files('util/sample_element_source.c'),
            'dependencies': [
                hse_test_support_dep,
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
            'sources': files('util/cheap_testlib.c'),
            'dependencies': [
                hse_test_support_dep,
            ],
        },
        'compression_test': {},
        'data_tree_test': {
            'sources': files('util/multithreaded_tester.c'),
        },
        'element_source_test': {
            'sources': files('util/sample_element_source.c'),
            'dependencies': [
                hse_test_support_dep,
            ],
        },
        'event_counter_test': {},
        'event_timer_test': {},
        'fmt_test': {},
        'hash_test': {},
        'hlog_unit_test': {},
        'keycmp_test': {},
        'keylock_test': {},
        'key_util_test': {},
        'list_test': {},
        'log2_test': {},
        'map_test': {},
        'parse_num_test': {},
        'perfc_test': {},
        'printbuf_test': {},
        'rbtree_test': {},
        'seqno_test': {
            'c_args': cc.get_supported_arguments('-Wno-clobbered'),
        },
        'spinlock_test': {
            'sources': files('util/thread_tester.c'),
        },
        'table_test': {},
        'timer_test': {},
        'token_bucket_test': {},
        'vlb_test': {},
        'workqueue_test': {},
        'xrand_test': {},
    },
}

unit_test_exes = []
foreach c, tests : components
    foreach t, params : tests
        t_exe = executable(
            t,
            c / '@0@.c'.format(t),
            params.get('sources', []),
            c_args: params.get('c_args', []),
            include_directories: params.get('include_directories', []),
            dependencies: [
                hse_mock_dep,
                hse_dependencies,
                hse_test_framework_dep,
                params.get('dependencies', []),
            ],
            gnu_symbol_visibility: 'hidden'
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
                    timeout: 300
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
                timeout: 300
            )
        endif
    endforeach
endforeach
