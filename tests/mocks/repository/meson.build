subdir('include')

mock_repository_sources = [
    files(
        'mock_c0cn.c',
        'mock_kbb_vbb.c',
        'mock_kvset_builder.c',
        'mock_kvset.c',
        'mock_log.c',
        'mock_mpool.c',
    ),
]

hse_mock_repository = static_library(
    'hse-mock-repository',
    mock_repository_sources,
    c_args: [
        '-DHSE_MOCKING=1',
        '-DCOMPNAME="kvdb"',
    ],
    include_directories: [
        hse_include_directories,
        hse_mock_include_directories,
        mock_repository_includes,
    ],
    dependencies: [
        hse_mock_dep,
        hse_dependencies,
    ],
)

hse_mock_repository_dep = declare_dependency(
    link_with: hse_mock_repository,
    include_directories: [
        mock_repository_includes,
    ],
)
