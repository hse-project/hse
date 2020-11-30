tools = {
	'cn_kbdump': {
		'dependencies': [
			mpool_dep,
		],
	},
	'cn_metrics': {},
	'cndb_log': {
		'dependencies': [
			mpool_dep,
		],
	},
	'kvck': {},
	'mdc_tool': {
		'dependencies': [
			mpool_dep,
		],
	},
	'mpool_profile': {
		'dependencies': [
			mpool_dep,
			m_dep,
		],
	},
}

common_tools_sources = []

common_tools_c_args = [
	'-DCOMPNAME="kvdb"',
	'-DXXH_PRIVATE_API',
]

common_tools_include_directories = [
	component_root_includes,
	hse_include_directories,
]

common_tools_dependencies = [
	hse_static_dep,
]

foreach t, params : tools
	t_sources = common_tools_sources
	t_sources += '@0@.c'.format(t)
	if 'sources' in params
		t_sources += params['sources']
	endif

	t_c_args = common_tools_c_args
	if 'c_args' in params
		t_c_args += params['c_args']
	endif

	t_include_directories = common_tools_include_directories
	if 'include_directories' in params
		t_include_directories += params['include_directories']
	endif

	t_dependencies = common_tools_dependencies
	if 'dependencies' in params
		t_dependencies += params['dependencies']
	endif

	executable(
		t,
		t_sources,
		c_args: t_c_args,
		include_directories: t_include_directories,
		dependencies: t_dependencies,
		install: true,
		install_rpath: exe_install_rpath,
	)
endforeach
