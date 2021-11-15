version_data = configuration_data({
    'build_version': build_version,
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
    'flags.h',
    'hse.h',
    'limits.h',
    'types.h',
    subdir: include_subdir,
)

if get_option('experimental')
    install_headers(
        'experimental.h',
        subdir: include_subdir,
    )
endif
