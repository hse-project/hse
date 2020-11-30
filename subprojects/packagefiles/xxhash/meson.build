project(
	'xxhash',
	['c'],
	version: '0.8.0',
	default_options: [
		'buildtype=debugoptimized',
	],
)

inc = include_directories('.')

xxhash = library(
	'xxhash',
	['xxhash.c'],
	c_args: [
		'-DXXH_INLINE_ALL',
	],
	include_directories: [
		inc,
	],
	version: meson.project_version(),
	install: true,
)

xxhash_dep = declare_dependency(
	link_with: xxhash,
	include_directories: [
		inc,
	],
	version: meson.project_version(),
)
