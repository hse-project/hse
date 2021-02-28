sources = files(
	'kmt.c',
)

c_args = [
	common_tools_c_args,
	'-DHDR_HISTOGRAM_C_FROM_SUBPROJECT=@0@'.format(HdrHistogram_c_from_subproject ? 1 : 0),
]

executable(
	'kmt',
	sources + tools_third_party_sources,
	c_args: c_args,
	include_directories: [
		common_tools_include_directories,
		tools_third_party_includes,
	],
	dependencies: [
		common_tools_dependencies,
		HdrHistogram_c_dep,
		libmongoc_dep,
		libbson_dep,
	],
	install: get_option('install-tools'),
	install_rpath: exe_install_rpath,
)

executable(
	'xkmt',
	sources + tools_third_party_sources,
	c_args: [
		c_args,
		'-DXKMT',
	],
	include_directories: [
		common_tools_include_directories,
		tools_third_party_includes,
	],
	dependencies: [
		common_tools_dependencies,
		HdrHistogram_c_dep,
		libmongoc_dep,
		libbson_dep,
	],
	install: get_option('install-tools'),
	install_rpath: exe_install_rpath,
)
