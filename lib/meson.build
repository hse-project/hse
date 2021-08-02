build_config_h_data = configuration_data({
    'SUPPORTS_ATTR_ALWAYS_INLINE': cc.has_function_attribute('always_inline'),
    'SUPPORTS_ATTR_FORMAT': cc.has_function_attribute('format'),
    'SUPPORTS_ATTR_PACKED': cc.has_function_attribute('packed'),
    'SUPPORTS_ATTR_ALIGNED': cc.has_function_attribute('aligned'),
    'SUPPORTS_ATTR_SECTION': cc.compiles(
        '''
        int x __attribute__((section(".read_mostly"))) = 0;
        ''',
        name: '__attribute__((section(".read_mostly")))',
    ),
    'SUPPORTS_ATTR_UNUSED': cc.has_function_attribute('unused'),
    'SUPPORTS_ATTR_USED': cc.has_function_attribute('used'),
    'SUPPORTS_ATTR_HOT': cc.has_function_attribute('hot'),
    'SUPPORTS_ATTR_COLD': cc.has_function_attribute('cold'),
    'SUPPORTS_ATTR_RETURNS_NONNULL': cc.has_function_attribute('returns_nonnull'),
    'SUPPORTS_ATTR_CONST': cc.has_function_attribute('const'),
    'SUPPORTS_ATTR_WEAK': cc.has_function_attribute('weak'),
    'SUPPORTS_ATTR_SENTINEL': cc.compiles(
        '''
        int __attribute__((sentinel))
        test_func(const char *fmt, ...)
        {
            return 0;
        }
        ''',
        name: '__attribute__((sentinel))',
    ),
    'SUPPORTS_ATTR_NO_SANITIZE_ALIGNMENT': cc.compiles(
        '''
        int __attribute__((no_sanitize("alignment")))
        test_func()
        {
            return 0;
        }
        ''',
        name: '__attribute__((no_sanitize("alignment")))',
    ),
    'WITH_COVERAGE': get_option('b_coverage'),
    'WITH_UBSAN': get_option('b_sanitize').contains('undefined'),
    'WITH_KVDB_CONF_EXTENDED': get_option('kvdb-conf-extended'),
})

build_config_h = configure_file(
    input: 'build_config.h.in',
    output: 'build_config.h',
    configuration: build_config_h_data,
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
subdir('wal')
subdir('mpool')
subdir('pidfile')

hse_sources = [
    build_config_h,
    binding_sources,
    c0_sources,
    lc_sources,
    config_sources,
    cn_sources,
    kvdb_sources,
    kvs_sources,
    wal_sources,
    mpool_sources,
    util_sources,
]

hse_c_args = [
    '-D_GNU_SOURCE=1',
    '-DCOMPNAME="kvdb"',
    '-DHSE_EXPERIMENTAL',
]

if get_option('experimental')
    hse_c_args += '-DHSE_EXPORT_EXPERIMENTAL'
endif

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
    cjson_dep,
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

if 'unit' in hse_tests
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
meson.override_dependency('@0@-static'.format(lib_name), hse_static_dep)

library_paths += meson.current_build_dir()
