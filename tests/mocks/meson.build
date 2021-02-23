mapi_idx_h = custom_target(
	'mapi-idx-generate',
	build_by_default: true,
	command: [
		mapi_idx_generate,
		'@OUTPUT@',
		'@DEPFILE@',
		'@PRIVATE_DIR@',
		meson.project_source_root(),
		get_option('mpool-include-dir'),
	],
	depfile: 'mapi_idx.h.mk',
	output: 'mapi_idx.h',
)

mocked_components = {
	'c0': meson.project_source_root() / 'lib' / 'c0',
	'cn': meson.project_source_root() / 'lib' / 'cn',
	'hse': meson.project_source_root() / 'include' / 'hse',
	'ikvdb': meson.project_source_root() / 'lib' / 'include' / 'hse_ikvdb',
	'kvdb': meson.project_source_root() / 'lib' / 'kvdb',
	'kvs': meson.project_source_root() / 'lib' / 'kvs',
	'mpool': get_option('mpool-include-dir'),
	'test-support': meson.project_source_root() / 'tests' / 'support' / 'include' / 'hse_test_support',
	'util': meson.project_source_root() / 'lib' / 'util' / 'include' / 'hse_util',
	'util-internal': meson.project_source_root() / 'lib' / 'util' / 'src',
}

mock_includes = include_directories('.')
mock_sources = [mapi_idx_h]

foreach mc, source_dir : mocked_components
	if not fs.exists(source_dir)
		error('@0@ does not exist'.format(source_dir))
	endif

	ut_mock_decl_files_output = run_command(
		ut_mock_decl_files,
		source_dir,
		check: true,
	).stdout().strip()

	if ut_mock_decl_files_output == ''
		continue
	endif

	mock_decl_files = ut_mock_decl_files_output.split('\n')

	foreach f : mock_decl_files
		stem = fs.stem(f)

		hdr = '@0@_ut.h'.format(stem)
		mock_decl = custom_target(
			'@0@.@1@-utpp-h'.format(mc, stem),
			build_by_default: true,
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
			output: hdr,
		)

		mock_sources += mock_decl

		src = '@0@_ut_impl.i'.format(stem)
		mock_impl = custom_target(
			'@0@.@1@-utpp-c'.format(mc, stem),
			build_by_default: true,
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
			output: src,
		)

		mock_sources += mock_impl
	endforeach
endforeach
