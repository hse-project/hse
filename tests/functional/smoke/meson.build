jq = find_program('jq', required: false)

tests = {
    # This one first
    'aloha': {
        'suites': ['smoke-ci'],
    },

    # The rest are ordered to run short tests first (release build)
    'simple_client1': {
        'suites': ['smoke-ci'],
        'depends': [
            tool_targets['simple_client'],
        ],
    },
    'kbdump': {
        'suites': ['smoke', 'nightly-small'],
        'depends': [
            tool_targets['cn_kbdump'],
            tool_targets['cn_metrics'],
            tool_targets['simple_client'],
        ],
    },
    'putget1': {
        'suites': ['smoke', 'nightly-small'],
        'depends': [
            tool_targets['putgetdel'],
        ],
    },
    'lcp_test': {
        'suites': ['smoke', 'nightly-small'],
        'depends': [
            tool_targets['pscan'],
        ],
    },
    'kvsdrop': {
        'suites': ['smoke', 'nightly-small'],
        'depends': [
            tool_targets['putbin'],
            tool_targets['cndb_log'],
        ],
    },
    'paths': {
        'suites': ['smoke-ci', 'nightly-small'],
        'enabled': jq.found(),
    },
    'longtestc0': {
        'suites': ['smoke', 'nightly-small'],
        'depends': [
            tool_targets['cn_metrics'],
            tool_targets['longtest'],
        ],
    },
    'longtest-cursor': {
        'suites': ['smoke', 'nightly-small'],
        'depends': [
            tool_targets['cn_metrics'],
            tool_targets['cndb_log'],
            tool_targets['longtest'],
        ],
    },
    'samples': {
        'suites': ['smoke-ci', 'nightly-small'],
        'depends': [
            sample_targets['ex1_create'],
            sample_targets['ex2_simple_ops'],
            sample_targets['ex3_cursor'],
            sample_targets['ex4_transactions'],
            sample_targets['ex5_large_val'],
            sample_targets['ex6_error_handling'],
            sample_targets['ex7_configuration'],
        ],
    },
    'droptomb1': {
        'suites': ['smoke', 'nightly-small'],
        'depends': [
            tool_targets['cn_metrics'],
            tool_targets['putbin'],
        ],
    },
    'seqno_order': {
        'suites': ['smoke', 'nightly-small'],
        'depends': [
            tool_targets['txput_flush'],
        ],
    },
    'droptomb2': {
        'suites': ['smoke', 'non-deterministic'],
        'depends': [
            tool_targets['cn_metrics'],
            tool_targets['putbin'],
        ],
    },
    'putget2': {
        'suites': ['smoke', 'nightly-small'],
        'depends': [
            tool_targets['putgetdel'],
        ],
    },
    'longtestcn': {
        'suites': ['smoke', 'nightly-small'],
        'depends': [
            tool_targets['cn_metrics'],
            tool_targets['longtest'],
        ],
    },
    'longtestcn2': {
        'suites': ['smoke', 'nightly-small'],
        'depends': [
            tool_targets['cn_metrics'],
            tool_targets['longtest'],
        ],
    },
    'mdc-test': {
        'suites': ['smoke', 'nightly-small'],
        'depends': [
            tool_targets['mdctest'],
            tool_targets['mdcperf'],
        ],
    },
    'key-imm-disc': {
        'suites': ['smoke', 'nightly-small'],
        'depends': [
            tool_targets['kmt'],
        ],
    },
    'kvt-simple': {
        'suites': ['smoke'],
        'depends': [
            tool_targets['kvt'],
        ],
    },
    'txn1': {
        'suites': ['smoke', 'nightly-small'],
        'depends': [
            tool_targets['ctxn_validation'],
        ],
    },
    'prefix-tree-shape1': {
        'suites': ['smoke', 'nightly-small'],
        'depends': [
            tool_targets['cn_metrics'],
            tool_targets['kmt'],
            tool_targets['putbin'],
        ],
    },
    'prefix-basic': {
        'suites': ['smoke', 'nightly-small'],
        'depends': [
            tool_targets['kmt'],
            tool_targets['pscan'],
        ],
    },
    'longtestkvmax': {
        'suites': ['smoke', 'nightly-small'],
        'depends': [
            tool_targets['cn_metrics'],
            tool_targets['longtest'],
        ],
    },
    'longtest-sync-cursor': {
        'suites': ['smoke', 'nightly-small'],
        'depends': [
            tool_targets['cn_metrics'],
            tool_targets['longtest'],
        ],
    },
    'longtest-sync': {
        'suites': ['smoke', 'nightly-small'],
        'depends': [
            tool_targets['cn_metrics'],
            tool_targets['longtest'],
        ],
    },
    'omf_encoder_perf': {
        'suites': ['smoke', 'nightly-small'],
        'depends': [
            tool_targets['omf_encoder_perf'],
        ],
    },
    'mcache-test': {
        'suites': ['smoke', 'nightly-small'],
        'depends': [
            tool_targets['mpiotest'],
        ],
    },
    'kvt-logreplay': {
        'suites': ['smoke'],
        'depends': [
            tool_targets['kvt'],
        ],
    },
    'kmt1': {
        'suites': ['smoke'],
        'depends': [
            tool_targets['kmt'],
        ],
    },
    'kmt-mpool': {
        'suites': ['smoke', 'nightly-small'],
        'depends': [
            tool_targets['kmt'],
        ],
    },
    'kvt-isolation': {
        'suites': ['smoke'],
        'depends': [
            tool_targets['kvt'],
        ],
    },
    'bonsai-insdel': {
        'suites': ['smoke', 'nightly-small'],
        'depends': [
            tool_targets['bnt'],
        ],
    },
    'large-values1': {
        'suites': ['smoke'],
        'depends': [
            tool_targets['cn_metrics'],
            tool_targets['kmt'],
            tool_targets['putbin'],
        ],
    },
    'cursor_test2': {
        'suites': ['smoke'],
        'depends': [
            tool_targets['range_read'],
        ],
    },
    'probe-test': {
        'suites': ['smoke'],
        'depends': [
            tool_targets['pfx_probe'],
        ],
    },
    'kvt-compression': {
        'suites': ['smoke'],
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
    #   ptree-test
}

foreach t, params : tests
    # Make sure every file is executable
    run_command(
        sh,
        '-c',
        '[ -x "@0@" ]'.format(meson.current_source_dir() / t + '.sh'),
        check: true
    )

    test(
        t,
        bash,
        args: [
            meson.current_source_dir() / '@0@.sh'.format(t),
        ],
        timeout: 1800,
        workdir: fs.parent(meson.current_source_dir()),
        suite: ['functional'] + params.get('suites', []),
        depends: [
            hse_cli_symlink,
            params.get('depends', []),
        ],
        env: environment({
            'HSE_TEST_RUNNER_RUNNER': 'bash',
        })
    )
endforeach
