tests = {
    'abort-destroy': {},
    'basic': {},
    'basic_lc': {},
    'basic_lc_cursors': {},
    'bind': {},
    'bind_commited': {},
    'bug.c0cn_dup_keys': {},
    'bug.skidx_not_in_c0_kvset': {},
    'bug.skidx_not_init': {},
    'bug.update_add_key': {},
    'bug.update_new_kvms': {},
    'bug.wrong_view_value': {},
    'cache': {},
    'cache_delay': {},
    'cn_seqno': {},
    'cn_update': {},
    'delfail': {},
    'ingested_key': {},
    'multcur_multview': {},
    'nostale': {},
    'pdel': {},
    'pos_stab': {},
    'ptomb_cursor': {},
    'ptomb_cursor2': {},
    'lc_cursor_test1': {
        'experimental': true,
    },
    'lc_test_fwd': {
        'experimental': true,
    },
    'lc_test_rev': {},
    'ptomb_snapshot_isolation': {},
    'rev_basic': {},
    'seek-del-put-next': {},
    'seek_tomb': {},
    'sfx_test_c0': {
        'experimental': true,
    },
    'sfx_test_c0cn': {
        'experimental': true,
    },
    'sfx_test_cn': {
        'experimental': true,
    },
    'sfx_test_tomb': {
        'experimental': true,
    },
    'sfx_test_txn': {
        'experimental': true,
    },
    'tombspan': {},
    'txcursor': {},
    'txdel': {},
    'txn-seek-del-put-next': {},
    'txn_and_non-txn': {
        'experimental': true,
    },
    'update_no_seek': {},
    'update_seek': {},
    'update_views': {},
}

foreach t, attrs : tests
    experimental = attrs.get('experimental', false)
    if experimental and not get_option('experimental')
        continue
    endif

    test(
        t,
        python,
        args: [
            '@0@.py'.format(t),
        ],
        depends: hse_python_depends,
        workdir: meson.current_source_dir(),
        suite: ['functional', 'python'],
        timeout: 300,
        env: environment({
            'HSE_TEST_RUNNER_RUNNER': 'python',
        })
    )
endforeach
