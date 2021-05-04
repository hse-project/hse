tests = [
    'abort-destroy',
    'basic',
    'basic_lc',
    'basic_lc_cursors',
    'bind',
    'bind_commited',
    'bug.c0cn_dup_keys',
    'bug.skidx_not_in_c0_kvset',
    'bug.skidx_not_init',
    'bug.update_add_key',
    'bug.update_new_kvms',
    'bug.wrong_view_value',
    'cache',
    'cache_delay',
    'cn_seqno',
    'cn_update',
    'delfail',
    'ingested_key',
    'multcur_multview',
    'nostale',
    'pdel',
    'pos_stab',
    'ptomb_cursor',
    'ptomb_cursor2',
    'rev_basic',
    'seek-del-put-next',
    'seek_tomb',
    'sfx_test_c0',
    'sfx_test_c0cn',
    'sfx_test_cn',
    'sfx_test_tomb',
    'sfx_test_txn',
    'ten_tx',
    'tombspan',
    'txcursor',
    'txdel',
    'txn-seek-del-put-next',
    'txn_and_non-txn',
    'update_no_seek',
    'update_seek',
    'update_views',
]

if not (get_option('bindings-python') and get_option('tests-kvdb') != '')
    warning(('HSE kvpy test suite disabled.'+
             '  Requires config options: bindings-python tests-kvdb'))
else
    foreach t : tests
        test(
            t,
            python,
            args: [
                '@0@.py'.format(t),
                '--kvdb-name', get_option('tests-kvdb'),
            ],
            depends: hse_python_depends,
            workdir: meson.current_source_dir(),
            is_parallel: false,
            suite: ['functional', 'kvpy'],
        )
    endforeach
endif
