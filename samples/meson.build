samples = [
    'ex1_create',
    'ex2_simple_ops',
    'ex3_cursor',
    'ex4_transactions',
    'ex5_large_val',
    'ex6_error_handling',
    'ex7_configuration',
]

sample_targets = {}

foreach s : samples
    if get_option('samples')
        e = executable(
            s,
            ['@0@.c'.format(s)],
            dependencies: [
                hse_dep,
            ],
            gnu_symbol_visibility: 'hidden',
        )

        sample_targets += { s: e }
    else
        sample_targets += { s: disabler() }
    endif
endforeach

executable_paths += meson.current_build_dir()
