project(
	'libbsd',
	['c'],
	version: '0.9.1',
	meson_version: '>=0.57',
)

extern = import('unstable_external_project')

run_command('autogen', check: true)

proj = extern.add_project(
	'configure',
	configure_options: [
		'--disable-static',
	],
)

libbsd_dep = proj.dependency('bsd')
