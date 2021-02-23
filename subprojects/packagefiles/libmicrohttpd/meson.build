project(
	'libmicrohttpd',
	['c'],
	version: '0.9.59',
	meson_version: '>=0.57',
)

extern = import('unstable_external_project')

configure_options = [
	'--disable-static',
	'--disable-doc',
	'--disable-examples',
	'--disable-curl',
	'--disable-largefile',
	'--disable-sendfile',
	'--disable-bauth',
	'--disable-dauth',
	'--disable-httpupgrade',
]

if get_option('default_library') == 'shared'
	configure_options += '--enable-shared'
	configure_options += '--disable-static'
elif get_option('default_library') == 'static'
	configure_options += '--disable-shared'
	configure_options += '--shared-static'
elif get_option('default_library') == 'both'
	configure_options += '--enable-shared'
	configure_options += '--enable-static'
endif

proj = extern.add_project(
	'configure',
	configure_options: configure_options,
)

libmicrohttpd_dep = proj.dependency('microhttpd')
