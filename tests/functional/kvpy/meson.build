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
    'lc_cursor_test1',
    'lc_test_fwd',
    'lc_test_rev',
    'ptomb_snapshot_isolation',
    'rev_basic',
    'seek-del-put-next',
    'seek_tomb',
    'sfx_test_c0',
    'sfx_test_c0cn',
    'sfx_test_cn',
    'sfx_test_tomb',
    'sfx_test_txn',
    'tombspan',
    'txcursor',
    'txdel',
    'txn-seek-del-put-next',
    'txn_and_non-txn',
    'update_no_seek',
    'update_seek',
    'update_views',
]

foreach t : tests
    home_dir = tests_dir / t
    if not fs.exists(home_dir)
        run_command(
            'mkdir',
            home_dir,
            check: true,
        )
    endif

    test(
        t,
        python,
        args: [
            '@0@.py'.format(t),
            '--home',
            home_dir,
        ],
        depends: hse_python_depends,
        workdir: meson.current_source_dir(),
        suite: ['functional', 'python'],
        timeout: 300,
    )
endforeach
