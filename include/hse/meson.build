hse_version_data = configuration_data({
	'build_version': '@0@@1@-@2@@3@'.format(
		meson.project_version(),
		build_vqual,
		build_rel,
		build_rtype,
	),
	'build_tag': build_tag,
	'build_sha': build_sha,
})

hse_version = configure_file(
	input: 'hse_version.h.in',
	output: 'hse_version.h',
	configuration: hse_version_data
)

install_headers(
	'hse_experimental.h',
	'hse_limits.h',
	'hse.h',
	'kvdb_perfc.h',
	hse_version,
	subdir: include_subdir,
)

if get_option('tests')
	subdir('mock')
endif
