_config_h_data = configuration_data()

_config_h_data.set(
    'WITH_COVERAGE',
    get_option('b_coverage'),
    description: 'Building with coverage support',
)

_config_h_data.set(
    'WITH_CJSON_FROM_SUBPROJECT',
    cJSON_from_subproject,
    description: 'Building with cJSON from subprojects',
)

_config_h_data.set(
    'HSE_CONF_EXTENDED',
    get_option('hse-conf-extended'),
    description: '[TESTING PURPOSES ONLY] Allow cparams and dparams to exist in hse.conf'
)

_config_h = configure_file(
    input: '_config.h.in',
    output: '_config.h',
    configuration: _config_h_data,
)

component_root_includes = include_directories('.')

lib_name = '@0@-@1@'.format(meson.project_name(), hse_major_version)
soversion = '0'

subdir('include')
subdir('binding')
subdir('config')
subdir('kvs')
subdir('util')
subdir('c0')
subdir('lc')
subdir('cn')
subdir('kvdb')
subdir('mpool')
subdir('pidfile')

hse_sources = [
    _config_h,
    binding_sources,
    c0_sources,
    lc_sources,
    config_sources,
    cn_sources,
    kvdb_sources,
    kvs_sources,
    mpool_sources,
    util_sources,
]

hse_c_args = [
    '-D_GNU_SOURCE=1',
    '-DCOMPNAME="kvdb"',
    '-DHSE_EXPERIMENTAL',
]

hse_include_directories = [
    ikvdb_includes,
    component_root_includes,
    public_includes,
    third_party_includes,
    util_includes,
    mpool_includes,
]

hse_dependencies = [
    # Add xxhash, lz4, and cJSON first to avoid potential inclusions from other
    # dependencies shadowing ours. xxhash must come before lz4 so we avoid
    # including xxhash.h from the lz4 source tree.
    xxhash_dep,
    lz4_dep,
    cJSON_dep,
    libbsd_dep,
    libcurl_dep,
    libmicrohttpd_dep,
    liburcu_bp_dep,
    libyaml_dep,
    m_dep,
    thread_dep,
    rbtree_dep,
    crc32c_dep,
    libhse_pidfile_dep,
]

hse = both_libraries(
    lib_name,
    hse_sources,
    c_args: hse_c_args,
    include_directories: hse_include_directories,
    dependencies: hse_dependencies,
    version: meson.project_version(),
    install: true,
    soversion: soversion,
    gnu_symbol_visibility: 'hidden',
)

hse_variables = {
    'source-root': meson.project_source_root(),
    'build-root': meson.project_build_root(),
}

hse_dep = declare_dependency(
    link_with: hse,
    version: meson.project_version(),
    sources: [
        version_h,
    ],
    include_directories: [
        public_includes,
    ],
    variables: hse_variables,
)

hse_static_dep = declare_dependency(
    link_with: hse.get_static_lib(),
    version: meson.project_version(),
    sources: [
        version_h,
    ],
    include_directories: [
        public_includes,
    ],
    variables: hse_variables,
)

if 'unit' in enabled_tests
    hse_mock_c_args = [
        '-DHSE_MOCKING=1',
    ]

    hse_mock_include_directories = [
        test_framework_includes,
        test_support_includes,
        mock_includes,
        tools_includes,
    ]

    hse_mock_sources = [
        test_support_sources,
        mock_sources,
    ]

    hse_mock = library(
        '@0@-mock-@1@'.format(meson.project_name(), hse_major_version),
        hse_sources + hse_mock_sources,
        c_args: hse_c_args + hse_mock_c_args,
        include_directories: hse_include_directories + hse_mock_include_directories,
        dependencies: hse_dependencies,
        soversion: soversion,
        version: meson.project_version(),
    )

    hse_mock_dep = declare_dependency(
        link_with: hse_mock,
        version: meson.project_version(),
        compile_args: hse_mock_c_args,
        sources: [
            version_h,
            mapi_idx_h,
            mock_sources,
        ],
        include_directories: [
            public_includes,
            hse_include_directories,
            hse_mock_include_directories,
        ],
    )
endif

pkg.generate(
    hse,
    description: 'Fast key-value storage for SSDs and persistent memory',
    filebase: lib_name,
    name: meson.project_name(),
    version: meson.project_version(),
    url: 'https://github.com/hse-project/hse',
    subdirs: [
        lib_name,
    ],
)

meson.override_dependency(lib_name, hse_dep)

library_paths += meson.current_build_dir()
