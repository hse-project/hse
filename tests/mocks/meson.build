# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# SPDX-FileCopyrightText: Copyright 2020 Micron Technology, Inc.

# Add header here if it needs to be mocked
mocked_headers = [
    meson.project_source_root() / 'include/hse/hse.h',
    meson.project_source_root() / 'lib/c0/c0sk_internal.h',
    meson.project_source_root() / 'lib/cn/blk_list.h',
    meson.project_source_root() / 'lib/cn/cn_cursor.h',
    meson.project_source_root() / 'lib/cn/cn_mblocks.h',
    meson.project_source_root() / 'lib/cn/cn_tree_compact.h',
    meson.project_source_root() / 'lib/cn/cn_tree_create.h',
    meson.project_source_root() / 'lib/cn/cn_tree_cursor.h',
    meson.project_source_root() / 'lib/cn/cn_tree.h',
    meson.project_source_root() / 'lib/cn/cn_tree_internal.h',
    meson.project_source_root() / 'lib/cn/cn_tree_iter.h',
    meson.project_source_root() / 'lib/cn/cn_tree_stats.h',
    meson.project_source_root() / 'lib/cn/csched_sp3.h',
    meson.project_source_root() / 'lib/cn/csched_sp3_work.h',
    meson.project_source_root() / 'lib/cn/hblock_builder.h',
    meson.project_source_root() / 'lib/cn/kblock_builder.h',
    meson.project_source_root() / 'lib/cn/kcompact.h',
    meson.project_source_root() / 'lib/cn/kvset.h',
    meson.project_source_root() / 'lib/cn/kvs_mblk_desc.h',
    meson.project_source_root() / 'lib/cn/mbset.h',
    meson.project_source_root() / 'lib/cn/route.h',
    meson.project_source_root() / 'lib/cn/spill.h',
    meson.project_source_root() / 'lib/cn/vblock_builder.h',
    meson.project_source_root() / 'lib/cn/wbt_builder.h',
    meson.project_source_root() / 'lib/cn/wbt_reader.h',
    meson.project_source_root() / 'lib/include/hse/ikvdb/c0.h',
    meson.project_source_root() / 'lib/include/hse/ikvdb/c0_kvmultiset.h',
    meson.project_source_root() / 'lib/include/hse/ikvdb/c0sk.h',
    meson.project_source_root() / 'lib/include/hse/ikvdb/cn.h',
    meson.project_source_root() / 'lib/include/hse/ikvdb/cn_kvdb.h',
    meson.project_source_root() / 'lib/include/hse/ikvdb/cndb.h',
    meson.project_source_root() / 'lib/include/hse/ikvdb/csched.h',
    meson.project_source_root() / 'lib/include/hse/ikvdb/ikvdb.h',
    meson.project_source_root() / 'lib/include/hse/ikvdb/kvset_builder.h',
    meson.project_source_root() / 'lib/include/hse/ikvdb/kvdb_ctxn.h',
    meson.project_source_root() / 'lib/include/hse/ikvdb/kvdb_meta.h',
    meson.project_source_root() / 'lib/include/hse/ikvdb/kvset_view.h',
    meson.project_source_root() / 'lib/include/hse/ikvdb/kvs.h',
    meson.project_source_root() / 'lib/include/hse/ikvdb/lc.h',
    meson.project_source_root() / 'lib/include/hse/ikvdb/sched_sts.h',
    meson.project_source_root() / 'lib/include/hse/ikvdb/wal.h',
    meson.project_source_root() / 'lib/kvdb/viewset.h',
    meson.project_source_root() / 'lib/kvdb/kvdb_keylock.h',
    meson.project_source_root() / 'lib/kvdb/kvdb_pfxlock.h',
    meson.project_source_root() / 'lib/lc/bonsai_iter.h',
    meson.project_source_root() / 'lib/mpool/include/hse/mpool/mpool.h',
    meson.project_source_root() / 'lib/util/include/hse/util/bin_heap.h',
    meson.project_source_root() / 'lib/util/include/hse/util/dax.h',
    meson.project_source_root() / 'lib/util/include/hse/util/hlog.h',
    meson.project_source_root() / 'lib/util/include/hse/util/keylock.h',
    meson.project_source_root() / 'lib/util/include/hse/util/perfc.h',
    meson.project_source_root() / 'lib/util/include/hse/util/platform.h',
    meson.project_source_root() / 'lib/util/include/hse/util/rmlock.h',
    meson.project_source_root() / 'lib/util/include/hse/util/slab.h',
    meson.project_source_root() / 'lib/util/include/hse/util/token_bucket.h',
    meson.project_source_root() / 'tests/mocks/include/hse/test/mock/allocation.h',
]

mapi_idx_h = custom_target(
    'mapi_idx.h',
    command: [
        mapi_idx_generate,
        '@OUTPUT@',
        meson.project_source_root(),
        '@PRIVATE_DIR@',
        '@0@'.format(' '.join(mocked_headers)),
    ],
    depend_files: mocked_headers,
    output: 'mapi_idx.h'
)

mocked_components = {
    'c0': meson.project_source_root() / 'lib/c0',
    'lc': meson.project_source_root() / 'lib/lc',
    'cn': meson.project_source_root() / 'lib/cn',
    'cndb': meson.project_source_root() / 'lib/cndb',
    'config': meson.project_source_root() / 'lib/config',
    'wal': meson.project_source_root() / 'lib/wal',
    'hse': meson.project_source_root() / 'include/hse',
    'ikvdb': meson.project_source_root() / 'lib/include/hse/ikvdb',
    'kvdb': meson.project_source_root() / 'lib/kvdb',
    'kvs': meson.project_source_root() / 'lib/kvs',
    'mpool': meson.project_source_root() / 'lib/mpool/include/hse/mpool',
    'mock': meson.project_source_root() / 'tests/mocks/include/hse/test/mock',
    'util': meson.project_source_root() / 'lib/util/include/hse/util',
    'util-internal': meson.project_source_root() / 'lib/util/lib',
}

mocked_includes = include_directories('.')
mocked_sources = [mapi_idx_h]

foreach mc, source_dir : mocked_components
    if not fs.exists(source_dir)
        error('@0@ does not exist'.format(source_dir))
    endif

    ut_mock_decl_files_output = run_command(
        ut_mock_decl_files,
        source_dir,
        check: true
    ).stdout().strip()

    if ut_mock_decl_files_output == ''
        continue
    endif

    mock_decl_files = ut_mock_decl_files_output.split('\n')

    foreach f : mock_decl_files
        stem = fs.stem(f)

        hdr = '@0@_ut.h'.format(stem)
        mock_decl = custom_target(
            hdr,
            input: f,
            command: [
                utpp,
                '--',
                '-h',
                '-o',
                '@OUTDIR@' / hdr,
                '@INPUT@',
            ],
            depend_files: [f],
            output: hdr
        )

        mocked_sources += mock_decl

        src = '@0@_ut_impl.i'.format(stem)
        mock_impl = custom_target(
            src,
            input: f,
            command: [
                utpp,
                '--',
                '-c',
                '-o',
                '@OUTDIR@' / src,
                '@INPUT@',
            ],
            depend_files: [f],
            output: src
        )

        mocked_sources += mock_impl
    endforeach
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
