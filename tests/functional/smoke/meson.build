

smoke_needs = 'cli tests-dir tools'
smoke_enabled = (get_option('cli') and
                 get_option('tests-dir') != '' and
                 get_option('tools'))

samples_needs = 'cli tests-dir samples'
samples_enabled = (get_option('cli') and
                   get_option('tests-dir') != '' and
                   get_option('samples'))

suites = {
    'smoke': {
        'enabled': smoke_enabled,
        'needs': smoke_needs,
        'tests': [
            # These two first
            'aloha',
            'version',

            # The rest are ordered to run short tests first (release build)
            'simple_client1',
            'putget1',
            'lcp_test',
            'kvsdrop',
            'longtestc0',
            'longtest-cursor',
            'samples',
            'droptomb1',
            'seqno_order',
            'droptomb2',
            'putget2',
            'longtestcn',
            'longtestcn2',
            'mdc-test',
            'key-imm-disc',
            'kvt-simple',
            'txn1',
            'prefix-tree-shape1',
            'prefix-basic',
            'longtestkvmax',
            'longtest-sync-cursor',
            'longtest-sync',
            'kvs-max',
            'omf_encoder_perf',
            'mcache-test',
            'kvt-logreplay',
            'kmt1',
            'kmt-mpool',
            'kvt-isolation',
            'bonsai-insdel',
            'large-values1',
            'cursor_test2',
            'probe-test',
            'kvt-compression',


            # These tests disabled until WAL is back:
            #
            #   kvt-logreplay
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
        ],
    },

    'samples': {
        'enabled': samples_enabled,
        'needs': samples_needs,
        'tests': [
            'samples'
        ],
    },
}

runner_script = find_program('smoke', required: true)

foreach suite, params : suites
    if not params['enabled']
        warning(('HSE functional test suite @0@ disabled.'+
                 '  Requires config options: @1@').format(suite, params['needs']))
    else
        foreach t : params['tests']

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
                suite: ['functional', suite],
            )
        endforeach
    endif
endforeach
