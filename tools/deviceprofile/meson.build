sources = files(
	'deviceprofile_app.c',
	'deviceprofile.c',
)

c_args = [
	common_tools_c_args,
	'-DHDR_HISTOGRAM_FROM_SUBPROJECT=@0@'.format(hdr_histogram_from_subproject ? 1 : 0),
]

executable(
	'deviceprofile',
	sources,
	c_args: c_args,
	include_directories: common_tools_include_directories,
	dependencies: [
		hse_static_dep,
		hdr_histogram_dep,
	],
	install: get_option('install-tools'),
	install_rpath: exe_install_rpath,
)
