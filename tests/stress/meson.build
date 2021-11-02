programs = {
    'stress_wal': {
        'small_tests': {
            'noclose_small': {
                'args': '-b 64 -c 5000000 -e 0 -i 0 -o 2 -r 0 -s 0 -t 0 -v 1024'.split(),
            },
            'txn_noclose_small': {
                'args': '-b 64 -c 5000000 -e 0 -i 0 -o 2 -r 0 -s 20 -t 1 -v 1024'.split(),
            },
            'disablewal_syncbeforeexit_small': {
                'args': '-b 64 -c 5000000 -e 0 -i 1 -o 2 -r 1 -s 0 -t 0 -v 1024'.split(),
            },
            'txn_disablewal_syncbeforeexit_small': {
                'args': '-b 64 -c 5000000 -e 0 -i 1 -o 2 -r 1 -s 16 -t 1 -v 1024'.split(),
            },
            'interleave_aborted_txns_noclose_small': {
                'args': '-b 64 -c 5000000 -e 0 -i 0 -o 2 -r 0 -s 16 -t 2 -v 1024'.split(),
            },
            'interleave_aborted_txns_disablewal_syncbeforeexit_small': {
                'args': '-b 64 -c 5000000 -e 0 -i 1 -o 2 -r 1 -s 16 -t 2 -v 1024'.split(),
            },
            'txn_noclose_tinyrecords_noclose_small': {
                'args': '-b 8 -c 9999000 -e 0 -i 0 -o 2 -r 0 -s 16 -t 1 -v 16'.split(),
            },
            'txn_noclose_tinyrecords_disablewal_syncbeforeexit_small': {
                'args': '-b 8 -c 9999000 -e 0 -i 1 -o 2 -r 1 -s 16 -t 1 -v 16'.split(),
            },
            'txn_noclose_1k2k_noclose_small': {
                'args': '-b 64 -c 5000000 -e 0 -i 0 -o 2 -r 0 -s 16 -t 1 -v 2048 -p 64 -q 1024'.split(),
            },
            'txn_noclose_1k2k_disablewal_syncbeforeexit_small': {
                'args': '-b 64 -c 5000000 -e 0 -i 1 -o 2 -r 1 -s 16 -t 1 -v 2048 -p 64 -q 1024'.split(),
            },
            'multikvs_noclose_small': {
                'args': '-b 64 -c 5000000 -e 0 -i 0 -o 2 -r 0 -s 64 -t 4 -v 1024'.split(),
            },
            'multikvs_disablewal_syncbeforeexit_small': {
                'args': '-b 64 -c 5000000 -e 0 -i 1 -o 2 -r 1 -s 64 -t 4 -v 1024'.split(),
            },
        },
        'nightly-tests': {
            'noclose_small': {
                'args': '-b 64 -c 3000000 -e 0 -i 0 -o 2 -r 0 -s 0 -t 0 -v 256'.split(),
            },
            'txn_noclose_small': {
                'args': '-b 64 -c 1000000 -e 0 -i 0 -o 2 -r 0 -s 20 -t 1 -v 256'.split(),
            },
            'disablewal_syncbeforeexit_small': {
                'args': '-b 64 -c 4000000 -e 0 -i 1 -o 2 -r 1 -s 0 -t 0 -v 256'.split(),
            },
            'txn_disablewal_syncbeforeexit_small': {
                'args': '-b 64 -c 5000000 -e 0 -i 1 -o 2 -r 1 -s 16 -t 1 -v 512'.split(),
            },
            'interleave_aborted_txns_noclose_small': {
                'args': '-b 64 -c 1000000 -e 0 -i 0 -o 2 -r 0 -s 16 -t 2 -v 256'.split(),
            },
            'interleave_aborted_txns_disablewal_syncbeforeexit_small': {
                'args': '-b 64 -c 5000000 -e 0 -i 1 -o 2 -r 1 -s 16 -t 2 -v 512'.split(),
            },
            'txn_noclose_tinyrecords_noclose_small': {
                'args': '-b 8 -c 4250000 -e 0 -i 0 -o 2 -r 0 -s 16 -t 1 -v 16'.split(),
            },
            'txn_noclose_tinyrecords_disablewal_syncbeforeexit_small': {
                'args': '-b 8 -c 5000000 -e 0 -i 1 -o 2 -r 1 -s 16 -t 1 -v 16'.split(),
            },
            'txn_noclose_1k2k_noclose_small': {
                'args': '-b 64 -c 1250000 -e 0 -i 0 -o 2 -r 0 -s 16 -t 1 -v 256 -p 64 -q 256'.split(),
            },
            'txn_noclose_1k2k_disablewal_syncbeforeexit_small': {
                'args': '-b 64 -c 5000000 -e 0 -i 1 -o 2 -r 1 -s 16 -t 1 -v 1024 -p 64 -q 256'.split(),
            },
            'multikvs_disablewal_syncbeforeexit_small': {
                'args': '-b 64 -c 475000 -e 0 -i 1 -o 2 -r 1 -s 64 -t 4 -v 512'.split(),
            },
        },
        'large_tests': {
            'noclose_large': {
                'args': '-b 64 -c 1000000000 -e 0 -i 0 -o 100 -r 0 -s 0 -t 0 -v 1024'.split(),
            },
            # 'txn_noclose_large': {
            #     'args': '-b 64 -c 1000000000 -e 0 -i 0 -o 100 -r 0 -s 0 -t 1 -v 1024'.split(),
            # },
            'disablewal_syncbeforeexit_large': {
                'args': '-b 64 -c 1000000000 -e 0 -i 1 -o 100 -r 1 -s 0 -t 0 -v 1024'.split(),
            },
            # 'txn_disablewal_syncbeforeexit_large': {
            #     'args': '-b 64 -c 1000000000 -e 0 -i 1 -o 100 -r 1 -s 0 -t 1 -v 1024'.split(),
            # },
            # 'multikvs_noclose_large': {
            #     'args': '-b 64 -c 1000000000 -e 0 -i 0 -o 100 -r 0 -s 128 -t 4 -v 1024'.split(),
            # },
            # 'multikvs_disablewal_syncbeforeexit_large': {
            #     'args': '-b 64 -c 1000000000 -e 0 -i 1 -o 100 -r 1 -s 128 -t 4 -v 1024'.split(),
            # },
        },
    },
    'stress_cursor': {
        'small_tests': {
            'create_cursor_small': {
                'args': '-b 64 -c 5000000 -d 1 -e 10000 -o 2 -v 1024'.split(),
            },
            'cursor_with_sync_small': {
                'args': '-b 64 -c 5000000 -d 5 -e 10000 -o 2 -v 1024'.split(),
            },
            'cursor_with_transactions_small': {
                'args': '-b 64 -c 100000 -d 6 -e 10000 -o 2 -s 10000 -v 1024'.split(),
            },
        },
        'nightly-tests': {
            'create_cursor_small': {
                'args': '-b 64 -c 2500000 -d 1 -e 1000 -o 2 -v 256'.split(),
            },
            'cursor_with_sync_small': {
                'args': '-b 64 -c 2500000 -d 5 -e 1000 -o 2 -v 512'.split(),
            },
            'cursor_with_transactions_small': {
                'args': '-b 64 -c 1000000 -d 6 -e 1000 -o 2 -s 1000 -v 256'.split(),
            },
        },
        'large_tests': {
            'create_cursor_large': {
                'args': '-b 64 -c 1000000000 -d 1 -e 20000 -o 100 -v 1024'.split(),
            },
        },
    },
    'stress_reverse_cursor': {
        'small_tests': {
            'reverse_cursor_committed_txn_small': {
                'args': '-b 64 -c 5000000 -d 2 -n 0 -o 2 -v 1024'.split(),
            },
            'reverse_cursor_uncommitted_txn_small': {
                'args': '-b 64 -c 5000000 -d 2 -n 1 -o 2 -v 1024'.split(),
            },
        },
        'nightly-tests': {
            'reverse_cursor_committed_txn_small': {
                'args': '-b 64 -c 1000000 -d 2 -n 0 -o 2 -v 256'.split(),
            },
            'reverse_cursor_uncommitted_txn_small': {
                'args': '-b 64 -c 1500000 -d 2 -n 1 -o 2 -v 256'.split(),
            },
        },
        'large_tests': {
            # 'reverse_cursor_committed_txn_large': {
            #     'args': '-b 64 -c 1000000000 -d 100 -n 0 -o 100 -v 1024'.split(),
            # },
            # 'reverse_cursor_uncommitted_txn_large': {
            #     'args': '-b 64 -c 1000000000 -d 100 -n 1 -o 100 -v 1024'.split(),
            # },
        },
    },
    'stress_reverse_cursor_unlimited_txn': {
        'small_tests': {
            'reverse_cursor_unlimited_txn_small': {
                'args': '-a 1000 -b 64 -c 5000000 -d 2 -o 2 -v 1024'.split(),
            },
        },
        'nightly-tests': {
            'reverse_cursor_unlimited_txn_small': {
                'args': '-a 1000 -b 64 -c 2500000 -d 2 -o 2 -v 256'.split(),
            },
        },
        'large_tests': {
            # 'reverse_cursor_unlimited_txn_large': {
            #     'args': '-a 1000 -b 64 -c 1000000000 -d 100 -o 100 -v 1024'.split(),
            # },
        },
    },
}

foreach p, p_params: programs
    e = executable(
        p,
        ['@0@.c'.format(p), 'stress_util.c'],
        c_args: [
            '-DHSE_EXPERIMENTAL',
        ],
        dependencies: [hse_internal_dep, hse_dependencies],
    )

    foreach t, t_params : p_params['small_tests']
        test(
            t,
            e,
            args: t_params['args'],
            is_parallel: false,
            suite: ['stress'],
            timeout: params.get('timeout', 600),
        )
    endforeach

    foreach t, t_params : p_params['large_tests']
        test(
            t,
            e,
            args: t_params['args'],
            is_parallel: false,
            suite: ['stress-large'],
            timeout: params.get('timeout', 3600),
        )
    endforeach

    foreach t, t_params : p_params['nightly-tests']
        test(
            t,
            e,
            args: t_params['args'],
            is_parallel: false,
            suite: ['nightly-small'],
            timeout: params.get('timeout', 1800),
        )
    endforeach
endforeach
