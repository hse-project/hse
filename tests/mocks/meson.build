if not cc.compiles('''
        void
        test(void) __attribute__((__annotate__("test")));
        ''',
        name: '__attribute__((__annotate__(...)))')
    hse_mock_dep = disabler()
    hse_mock_repository_dep = disabler()
    subdir_done()
endif

subdir('cli')

# Add header here if it needs to be mocked
mocked_headers = {
    'hse': meson.project_source_root() / 'include/hse/hse.h',
    'blk_list': meson.project_source_root() / 'lib/cn/blk_list.h',
    'c0sk_internal': meson.project_source_root() / 'lib/c0/c0sk_internal.h',
    'cn_cursor': meson.project_source_root() / 'lib/cn/cn_cursor.h',
    'cn_mblocks': meson.project_source_root() / 'lib/cn/cn_mblocks.h',
    'cn_tree_compact': meson.project_source_root() / 'lib/cn/cn_tree_compact.h',
    'cn_tree_create': meson.project_source_root() / 'lib/cn/cn_tree_create.h',
    'cn_tree_cursor': meson.project_source_root() / 'lib/cn/cn_tree_cursor.h',
    'cn_tree': meson.project_source_root() / 'lib/cn/cn_tree.h',
    'cn_tree_internal': meson.project_source_root() / 'lib/cn/cn_tree_internal.h',
    'cn_tree_iter': meson.project_source_root() / 'lib/cn/cn_tree_iter.h',
    'cn_tree_stats': meson.project_source_root() / 'lib/cn/cn_tree_stats.h',
    'csched_sp3': meson.project_source_root() / 'lib/cn/csched_sp3.h',
    'csched_sp3_work': meson.project_source_root() / 'lib/cn/csched_sp3_work.h',
    'hblock_builder': meson.project_source_root() / 'lib/cn/hblock_builder.h',
    'hblock_reader': meson.project_source_root() / 'lib/cn/hblock_reader.h',
    'kblock_builder': meson.project_source_root() / 'lib/cn/kblock_builder.h',
    'kcompact': meson.project_source_root() / 'lib/cn/kcompact.h',
    'kvset': meson.project_source_root() / 'lib/cn/kvset.h',
    'mblk_desc': meson.project_source_root() / 'lib/cn/kvs_mblk_desc.h',
    'mbset': meson.project_source_root() / 'lib/cn/mbset.h',
    'route': meson.project_source_root() / 'lib/cn/route.h',
    'spill': meson.project_source_root() / 'lib/cn/spill.h',
    'vblock_builder': meson.project_source_root() / 'lib/cn/vblock_builder.h',
    'wbt_builder': meson.project_source_root() / 'lib/cn/wbt_builder.h',
    'wbt_reader': meson.project_source_root() / 'lib/cn/wbt_reader.h',
    'c0': meson.project_source_root() / 'lib/include/hse/ikvdb/c0.h',
    'c0kvms': meson.project_source_root() / 'lib/include/hse/ikvdb/c0_kvmultiset.h',
    'c0sk': meson.project_source_root() / 'lib/include/hse/ikvdb/c0sk.h',
    'cn': meson.project_source_root() / 'lib/include/hse/ikvdb/cn.h',
    'cn_kvdb': meson.project_source_root() / 'lib/include/hse/ikvdb/cn_kvdb.h',
    'cndb': meson.project_source_root() / 'lib/include/hse/ikvdb/cndb.h',
    'csched': meson.project_source_root() / 'lib/include/hse/ikvdb/csched.h',
    'ikvdb': meson.project_source_root() / 'lib/include/hse/ikvdb/ikvdb.h',
    'kvset_builder': meson.project_source_root() / 'lib/include/hse/ikvdb/kvset_builder.h',
    'kvdb_ctxn': meson.project_source_root() / 'lib/include/hse/ikvdb/kvdb_ctxn.h',
    'kvdb_meta': meson.project_source_root() / 'lib/include/hse/ikvdb/kvdb_meta.h',
    'kvset_view': meson.project_source_root() / 'lib/include/hse/ikvdb/kvset_view.h',
    'kvs': meson.project_source_root() / 'lib/include/hse/ikvdb/kvs.h',
    'lc': meson.project_source_root() / 'lib/include/hse/ikvdb/lc.h',
    'sched_sts': meson.project_source_root() / 'lib/include/hse/ikvdb/sched_sts.h',
    'wal': meson.project_source_root() / 'lib/include/hse/ikvdb/wal.h',
    'viewset': meson.project_source_root() / 'lib/kvdb/viewset.h',
    'kvdb_keylock': meson.project_source_root() / 'lib/kvdb/kvdb_keylock.h',
    'kvdb_pfxlock': meson.project_source_root() / 'lib/kvdb/kvdb_pfxlock.h',
    'bonsai_iter': meson.project_source_root() / 'lib/lc/bonsai_iter.h',
    'mpool': meson.project_source_root() / 'lib/mpool/include/hse/mpool/mpool.h',
    'alloc': meson.project_source_root() / 'lib/util/include/hse/util/alloc.h',
    'bin_heap': meson.project_source_root() / 'lib/util/include/hse/util/bin_heap.h',
    'dax': meson.project_source_root() / 'lib/util/include/hse/util/dax.h',
    'hlog': meson.project_source_root() / 'lib/util/include/hse/util/hlog.h',
    'keylock': meson.project_source_root() / 'lib/util/include/hse/util/keylock.h',
    'perfc': meson.project_source_root() / 'lib/util/include/hse/util/perfc.h',
    'platform': meson.project_source_root() / 'lib/util/include/hse/util/platform.h',
    'rmlock': meson.project_source_root() / 'lib/util/include/hse/util/rmlock.h',
    'slab': meson.project_source_root() / 'lib/util/include/hse/util/slab.h',
    'token_bucket': meson.project_source_root() / 'lib/util/include/hse/util/token_bucket.h',
    'allocation': meson.project_source_root() / 'tests/mocks/include/hse/test/mock/allocation.h',
}

mapi_inputs = []
foreach group, file : mocked_headers
    mapi_inputs += file
endforeach

mapi_idx_h = custom_target(
    'mapi_idx.h',
    input: mapi_inputs,
    command: [
        mkmock,
        '--builddir',
        meson.global_build_root(),
        '--output',
        '@OUTPUT@',
        'symbol-table',
        '@INPUT@',
    ],
    output: 'mapi_idx.h'
)

mocked_includes = include_directories('.')
mocked_sources = [mapi_idx_h]

foreach group, file : mocked_headers
    assert(fs.exists(file), '@0@ does not exist'.format(file))

    stem = fs.stem(file)

    hdr = '@0@_ut.h'.format(stem)
    mock_decl = custom_target(
        '@0@.h'.format(stem),
        input: file,
        command: [
            mkmock,
            '--builddir',
            meson.global_build_root(),
            '--output',
            '@OUTDIR@' / hdr,
            'header',
            group,
            '@INPUT@',
        ],
        output: hdr
    )

    mocked_sources += mock_decl

    src = '@0@_ut_impl.i'.format(stem)
    mock_impl = custom_target(
        '@0@.i'.format(stem),
        input: file,
        command: [
            mkmock,
            '--builddir',
            meson.global_build_root(),
            '--output',
            '@OUTDIR@' / src,
            'source',
            group,
            '@INPUT@',
        ],
        output: src
    )

    mocked_sources += mock_impl
endforeach

subdir('include')
subdir('lib')

hse_mock_c_args = ['-DHSE_MOCKING=1']

hse_mock_include_directories = [
    mock_includes,
    mocked_includes,
]

hse_mock = static_library(
    '@0@-mock'.format(lib_name),
    hse_sources,
    mock_sources,
    mocked_sources,
    c_args: hse_mock_c_args,
    include_directories: [
        hse_include_directories,
        hse_mock_include_directories,
    ],
    dependencies: [
        hse_dependencies,
        hse_test_framework_dep,
    ],
    gnu_symbol_visibility: 'hidden'
)

hse_mock_dep = declare_dependency(
    link_with: hse_mock,
    compile_args: hse_mock_c_args,
    sources: mocked_sources,
    include_directories: [
        hse_include_directories,
        hse_mock_include_directories,
    ]
)
