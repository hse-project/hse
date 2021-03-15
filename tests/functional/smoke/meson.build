

smoke_needs = 'cli tests-kvdb tools'
smoke_enabled = (get_option('cli') and
                 get_option('tests-kvdb') != '' and
                 get_option('tools'))

samples_needs = 'cli tests-kvdb samples'
samples_enabled = (get_option('cli') and
                   get_option('tests-kvdb') != '' and
                   get_option('samples'))

suites = {
    'smoke': {
        'enabled': smoke_enabled,
        'needs': smoke_needs,
        'tests': [
            # These two first
            'aloha',
            'version',

            # The rest are ordered to run short tests first
            'simple_client1',
            'putget1',
            'lcp_test',
            'longtestc0',
            'longtest-cursor',
            'kvsdrop',
            'seqno_order',
            'samples',
            'droptomb1',
            'key-imm-disc',
            'droptomb2',
            'putget2',
            'omf_encoder_perf',
            'prefix-basic',
            'probe-test',
            'longtestcn',
            'longtest-sync',
            'longtestcn2',
            'longtest-sync-cursor',
            'prefix-tree-shape1',
            'kvt-simple',
            'txn1',
            'longtestkvmax',
            'kmt1',
            'large-values1',
            'kvt-isolation',
            'kvt-logreplay',
            'cursor_test2',
            'kvt-compression',
            'kvs-max',

            # These tests disabled until WAL is back:
            #
            #   kvt-logreplay
            #   c1-correctness
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
            test(
                t,
                runner_script,
                args: [
                    '-d', meson.current_build_dir(),
                    '-m', get_option('tests-kvdb'),
                    t,
                ],
		timeout: 1800,
                is_parallel: false,
                suite: ['functional', suite],
            )
        endforeach
    endif
endforeach


