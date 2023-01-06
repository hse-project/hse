# Options that are interesting to view in extended version output
build_opts = [
    '-Dc_args=\\"@0@\\"'.format(' '.join(get_option('c_args'))),
    '-Dc_link_args=\\"@0@\\"'.format(' '.join(get_option('c_link_args'))),
    '-Dforce_fallback_for=@0@'.format(','.join(get_option('force_fallback_for'))),
]
foreach opt : ['buildtype', 'debug', 'optimization', 'b_lto', 'b_ndebug', 'b_pgo', 'experimental']
    build_opts += '-D@0@=@1@'.format(opt, get_option(opt))
endforeach

if not cc.has_function_attribute('packed')
    error('Compiler must support the "packed" attribute')
endif

build_config_h_data = configuration_data({
    'build_config': '"@0@"'.format(' '.join(build_opts)),
    'SUPPORTS_ATTR_ALIGNED': cc.has_function_attribute('aligned'),
    'SUPPORTS_ATTR_ALWAYS_INLINE': cc.has_function_attribute('always_inline'),
    'SUPPORTS_ATTR_COLD': cc.has_function_attribute('cold'),
    'SUPPORTS_ATTR_CONST': cc.has_function_attribute('const'),
    'SUPPORTS_ATTR_FORMAT': cc.has_function_attribute('format'),
    'SUPPORTS_ATTR_HOT': cc.has_function_attribute('hot'),
    'SUPPORTS_ATTR_NOINLINE': cc.has_function_attribute('noinline'),
    'SUPPORTS_ATTR_NONNULL': cc.has_function_attribute('nonnull'),
    'SUPPORTS_ATTR_PACKED': true,
    'SUPPORTS_ATTR_RETURNS_NONNULL': cc.has_function_attribute('returns_nonnull'),
    'SUPPORTS_ATTR_SECTION': cc.compiles(
        '''
        int x __attribute__((__section__(".read_mostly"))) = 0;
        ''',
        name: '__attribute__((__section__(".read_mostly")))',
    ),
    'SUPPORTS_ATTR_SENTINEL': cc.compiles(
        '''
        int __attribute__((__sentinel__))
        test_func(const char *fmt, ...)
        {
            return 0;
        }
        ''',
        name: '__attribute__((__sentinel__))',
    ),
    'SUPPORTS_ATTR_UNUSED': cc.has_function_attribute('unused'),
    'SUPPORTS_ATTR_USED': cc.has_function_attribute('used'),
    'SUPPORTS_ATTR_WARN_UNUSED_RESULT': cc.has_function_attribute('warn_unused_result'),
    'SUPPORTS_ATTR_WEAK': cc.has_function_attribute('weak'),
    'HAVE_PMEM': libpmem_dep.found(),
    'WITH_COVERAGE': get_option('b_coverage'),
    'WITH_INVARIANTS': get_option('debug'),
    'WITH_LTO': get_option('b_lto'),
    'WITH_UBSAN': get_option('b_sanitize').contains('undefined'),
})

build_config_h = configure_file(
    input: 'build_config.h.in',
    output: 'build_config.h',
    configuration: build_config_h_data,
)

component_root_includes = include_directories('.')

lib_name = '@0@-@1@'.format(meson.project_name(), hse_major_version)
soversion = '0'

subdir('util')
subdir('error')
subdir('logging')
subdir('config')
subdir('include')
subdir('binding')
subdir('kvs')
subdir('c0')
subdir('lc')
subdir('cn')
subdir('cndb')
subdir('kvdb')
subdir('wal')
subdir('mpool')
subdir('pidfile')
subdir('rest')

hse_sources = [
    build_config_h,
    binding_sources,
    c0_sources,
    lc_sources,
    cn_sources,
    cndb_sources,
    kvdb_sources,
    kvs_sources,
    wal_sources,
    mpool_sources,
    util_sources,
]

hse_include_directories = [
    ikvdb_includes,
    component_root_includes,
    public_includes,
    util_includes,
    mpool_includes,
]

hse_dependencies = [
    # Add xxhash, lz4, and cJSON first to avoid potential inclusions from other
    # dependencies shadowing ours. xxhash must come before lz4 so we avoid
    # including xxhash.h from the lz4 source tree.
    xxhash_dep,
    liblz4_dep,
    cjson_dep,
    cjson_utils_dep,
    hyperloglog_dep,
    libbsd_dep,
    hse_config_dep,
    hse_error_dep,
    hse_logging_dep,
    hse_pidfile_dep,
    hse_rest_dep,
    liburcu_bp_dep,
    m_dep,
    threads_dep,
    rbtree_dep,
    crc32c_dep,
    xoroshiro_dep,
    libpmem_dep,
]

hse = library(
    lib_name,
    hse_sources,
    include_directories: hse_include_directories,
    dependencies: hse_dependencies,
    version: meson.project_version(),
    install: true,
    soversion: soversion,
    gnu_symbol_visibility: 'hidden',
)

hse_dep = declare_dependency(
    link_with: hse,
    version: meson.project_version(),
    sources: [
        version_h,
    ],
    include_directories: [
        public_includes,
    ]
)

if get_option('tools').allowed() or get_option('tests')
    if get_option('default_library') == 'shared'
        hse_internal = static_library(
            '@0@-internal'.format(lib_name),
            objects: hse.extract_all_objects(recursive: true),
            gnu_symbol_visibility: 'hidden'
        )
    elif get_option('default_library') == 'static'
        hse_internal = hse
    elif get_option('default_library') == 'both'
        hse_internal = hse.get_static_lib()
    endif

    hse_internal_dep = declare_dependency(
        link_with: hse_internal,
        version: meson.project_version(),
        sources: [
            version_h,
        ],
        include_directories: hse_include_directories,
        dependencies: hse_dependencies
    )
else
    hse_internal_dep = disabler()
endif

pkg.generate(
    hse,
    name: 'Heterogeneous-Memory Storage Engine',
    description: 'HSE is a fast embeddable key-value store designed for SSDs and persistent memory.',
    filebase: lib_name,
    version: meson.project_version(),
    url: 'https://github.com/hse-project',
    subdirs: [
        lib_name,
    ]
)

meson.override_dependency(lib_name, hse_dep)

library_paths += meson.current_build_dir()
