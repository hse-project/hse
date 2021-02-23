sources = files(
	'kmt.c',
)

executable(
	'kmt',
	sources + tools_third_party_sources,
	c_args: common_tools_c_args,
	include_directories: [
		common_tools_include_directories,
		tools_third_party_includes,
	],
	dependencies: [
		hse_static_dep,
		hdr_histogram_dep,
		libmongoc_dep,
		libbson_dep,
	],
	install: get_option('install-tools'),
	install_rpath: exe_install_rpath,
)
