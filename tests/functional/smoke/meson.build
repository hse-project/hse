tests = {
    # These two first
    'aloha': {
        'suites': ['smoke-ci'],
    },
    'version': {
        'suites': ['smoke-ci'],
    },

    # The rest are ordered to run short tests first (release build)
    'simple_client1': {
        'suites': ['smoke-ci'],
        'depends': [
            tool_targets['simple_client'],
        ],
    },
    'putget1': {
        'depends': [
            tool_targets['putgetdel'],
        ],
    },
    'lcp_test': {
        'depends': [
            tool_targets['pscan'],
        ],
    },
    'kvsdrop': {
        'depends': [
            tool_targets['putbin'],
            tool_targets['cndb_log'],
        ],
    },
    'longtestc0': {
        'depends': [
            tool_targets['longtest'],
            tool_targets['cn_metrics'],
        ],
    },
    'longtest-cursor': {
        'depends': [
            tool_targets['longtest'],
            tool_targets['cndb_log'],
            tool_targets['cn_metrics'],
        ],
    },
    'samples': {
        'depends': [
            sample_targets['ex1_create'],
            sample_targets['ex2_simple_ops'],
            sample_targets['ex3_cursor'],
            sample_targets['ex4_transactions'],
            sample_targets['ex5_large_val'],
        ],
    },
    'droptomb1': {
        'depends': [
            tool_targets['putbin'],
            tool_targets['cn_metrics'],
        ],
    },
    'seqno_order': {
        'depends': [
            tool_targets['txput_flush'],
        ],
    },
    'droptomb2': {
        'suites': ['non-deterministic'],
        'depends': [
            tool_targets['putbin'],
            tool_targets['cn_metrics'],
        ],
    },
    'putget2': {
        'depends': [
            tool_targets['putgetdel'],
        ],
    },
    'longtestcn': {
        'depends': [
            tool_targets['longtest'],
            tool_targets['cn_metrics'],
        ],
    },
    'longtestcn2': {
        'depends': [
            tool_targets['longtest'],
            tool_targets['cn_metrics'],
        ],
    },
    'mdc-test': {
        'depends': [
            tool_targets['mdctest'],
            tool_targets['mdcperf'],
        ],
    },
    'key-imm-disc': {
        'depends': [
            tool_targets['kmt'],
        ],
    },
    'kvt-simple': {
        'depends': [
            tool_targets['kvt'],
        ],
    },
    'txn1': {
        'depends': [
            tool_targets['ctxn_validation'],
        ],
    },
    'prefix-tree-shape1': {
        'depends': [
            tool_targets['kmt'],
            tool_targets['putbin'],
            tool_targets['cn_metrics'],
        ],
    },
    'prefix-basic': {
        'depends': [
            tool_targets['kmt'],
            tool_targets['pscan'],
        ],
    },
    'longtestkvmax': {
        'depends': [
            tool_targets['longtest'],
            tool_targets['cn_metrics'],
        ],
    },
    'longtest-sync-cursor': {
        'depends': [
            tool_targets['longtest'],
            tool_targets['cn_metrics'],
        ],
    },
    'longtest-sync': {
        'depends': [
            tool_targets['longtest'],
            tool_targets['cn_metrics'],
        ],
    },
    'kvs-max': {
        'depends': [
            tool_targets['kmt'],
        ],
    },
    'omf_encoder_perf': {
        'depends': [
            tool_targets['omf_encoder_perf'],
        ],
    },
    'mcache-test': {
        'depends': [
            tool_targets['mpiotest'],
        ],
    },
    'kvt-logreplay': {
        'depends': [
            tool_targets['kvt'],
        ],
    },
    'kmt1': {
        'depends': [
            tool_targets['kmt'],
        ],
    },
    'kmt-mpool': {
        'depends': [
            tool_targets['kmt'],
        ],
    },
    'kvt-isolation': {
        'depends': [
            tool_targets['kvt'],
        ],
    },
    'bonsai-insdel': {
        'depends': [
            tool_targets['bnt'],
        ],
    },
    'large-values1': {
        'depends': [
            tool_targets['kmt'],
            tool_targets['cn_metrics'],
            tool_targets['putbin'],
        ],
    },
    'cursor_test2': {
        'depends': [
            tool_targets['kvck'],
            tool_targets['range_read'],
        ],
    },
    'probe-test': {
        'depends': [
            tool_targets['pfx_probe'],
        ],
    },
    'kvt-compression': {
        'depends': [
            tool_targets['kvt'],
        ],
    },

    #
    # These tests started failing around 2021-03-10:
    #
    #   cursor_test1
    #   txn_thrash
    #
    # These tests also fail, not sure when they started to fail:
    #
    #   prefix-spill
    #   prefix-pivot
    #   ptree-test
}

runner_script = find_program('smoke', required: true)

foreach t, params : tests
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
        runner_script,
        args: [
            '-d', meson.current_build_dir(),
            '-m', home_dir,
            t,
        ],
        timeout: 1800,
        is_parallel: true,
        suite: ['functional', 'smoke'] + params.get('suites', []),
        depends: [
            hse_cli_symlink,
            params.get('depends', []),
        ],
    )
endforeach
