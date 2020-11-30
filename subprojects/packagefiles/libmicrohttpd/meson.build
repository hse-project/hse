project(
	'libmicrohttpd',
	['c'],
	version: '0.9.59',
	meson_version: '>=0.57',
)

extern = import('unstable_external_project')

proj = extern.add_project(
	'configure',
	configure_options: [
		'--disable-static',
		'--disable-doc',
		'--disable-examples',
		'--disable-curl',
		'--disable-largefile',
		'--disable-sendfile',
		'--disable-bauth',
		'--disable-dauth',
		'--disable-httpupgrade',
	],
)

libmicrohttpd_dep = proj.dependency('microhttpd')
