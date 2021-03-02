version_data = configuration_data({
    'build_version': '@0@@1@-@2@@3@'.format(
        meson.project_version(),
        build_vqual,
        build_rel,
        build_rtype,
    ),
    'build_tag': build_tag,
    'build_sha': build_sha,
})

version_h = configure_file(
    input: 'hse_version.h.in',
    output: 'hse_version.h',
    configuration: version_data,
)

install_headers(
    version_h,
    'hse.h',
    'hse_limits.h',
    'hse_experimental.h',
    'kvdb_perfc.h',
    subdir: include_subdir,
)
