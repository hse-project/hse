version_data = configuration_data({
    'build_version': '@0@@1@-@2@@3@'.format(
        meson.project_version(),
        build_vqual,
        build_rel,
        build_rtype,
    ),
    'build_tag': build_tag,
    'build_sha': build_sha,
    'major_version': hse_major_version,
    'minor_version': hse_minor_version,
    'patch_version': hse_patch_version,
})

version_h = configure_file(
    input: 'version.h.in',
    output: 'version.h',
    configuration: version_data,
)

install_headers(
    version_h,
    'hse.h',
    'limits.h',
    'flags.h',
    'types.h',
    subdir: include_subdir,
)
