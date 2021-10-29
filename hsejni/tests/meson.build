hsejni_parse_test = executable(
    'hsejni_parse_test',
    ['hsejni_parse_test.c'],
    c_args: [
        '-DCOMPNAME="hsejni"',
    ],
    dependencies: [
        hse_mock_dep,
        hsejni_dep,
        libhse_cli_dep,
        cjson_dep,
        libbsd_dep,
        hse_test_framework_dep,
    ],
)

test(
    'hsejni_parse_test',
    hsejni_parse_test,
    suite: ['unit', 'hsejni'],
)
