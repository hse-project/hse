project(
	'libyaml',
	['c'],
	version: '0.1.7',
	meson_version: '>=0.57',
)

extern = import('unstable_external_project')

run_command('bootstrap', check: true)

proj = extern.add_project(
	'configure',
	configure_options: [
		'--disable-static',
	],
)

libyaml_dep = proj.dependency('yaml')
