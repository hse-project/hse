util_mock_includes = include_directories('.')

util_mock_sources = []

ut_mock_decl_files_output = run_command(
	ut_mock_decl_files,
	fs.parent(meson.current_source_dir()),
	check: true,
).stdout().strip()

if ut_mock_decl_files_output == ''
	subdir_done()
endif

mock_decl_files = ut_mock_decl_files_output.split('\n')

foreach f : mock_decl_files
	stem = fs.stem(f)

	hdr = '@0@_ut.h'.format(stem)
	mock_decl = custom_target(
		'@0@.@1@-utpp-h'.format('util', stem),
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

	util_mock_sources += mock_decl

	src = '@0@_ut_impl.i'.format(stem)
	mock_impl = custom_target(
		'@0@.@1@-utpp-c'.format('util', stem),
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

	util_mock_sources += mock_impl
endforeach
