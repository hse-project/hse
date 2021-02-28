examples = [
    'ex1_create',
    'ex2_simple_ops',
    'ex3_cursor',
    'ex4_transactions',
    'ex5_large_val',
]

foreach e : examples
    executable(
        e,
        ['@0@.c'.format(e)],
        dependencies: [
            hse_dep,
        ],
        include_directories: [
            public_includes,
        ]
    )
endforeach
