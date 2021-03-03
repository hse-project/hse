if not get_option('cli') or not get_option('tools')
    error('Both the cli and tools options must be set to true in order to run smoke tests')
endif

tests = [
    'aloha',
    # 'c1-correctness',
    'coalesce',
    'compaction',
    'cursor_test1',
    'cursor_test2',
    'droptomb1',
    'droptomb2',
    'key-imm-disc',
    'kmt1',
    'kmtc0',
    'kmt-ins-1g',
    'kmtw05',
    'kmtw20',
    'kmtw50',
    'kvsdrop',
    'kvs-max',
    'kvt-compression',
    'kvt-isolation',
    'kvt-logreplay',
    'kvt-simple',
    'large-values1',
    'lcp_test',
    'longtest60',
    'longtestc0',
    'longtestcn',
    'longtestcn2',
    'longtest-cursor',
    'longtestkvmax',
    'longtest-sync',
    'longtest-sync-cursor',
    'mpft-correctness',
    'prefix-basic',
    'prefix-pivot',
    'prefix-spill',
    'prefix-tree-shape1',
    'probe-test',
    'ptree-test',
    'putget1',
    'putget2',
    'samples',
    'seqno_order',
    'simple_client1',
    'txn1',
    'txn_thrash',
    'version',
    'zlenval1',
]

smoke = find_program('smoke', required: true)

foreach t : tests
    test(
        t,
        smoke,
        args: [
            '--logdir',
            meson.current_build_dir() / 'smokelogs',
            t,
        ],
        is_parallel: false,
        suite: ['functional', 'smoke'],
    )
endforeach
