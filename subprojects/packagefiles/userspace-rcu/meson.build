project(
	'userspace-rcu',
	['c'],
	version: '0.10.3',
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

liburcu_bp_dep = proj.dependency('urcu-bp')
