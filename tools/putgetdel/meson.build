sources = files(
	'putgetdel.c',
	'..' / 'key_generation.c',
)

executable(
	'putgetdel',
	sources,
	c_args: common_tools_c_args,
	include_directories: common_tools_include_directories,
	dependencies: [
		hse_static_dep,
	],
	install: get_option('install-tools'),
	install_rpath: exe_install_rpath,
)
