doxygen = find_program('doxygen', required: get_option('docs'))
if not doxygen.found()
    subdir_done()
endif

input_files = [meson.project_build_root() / 'include/hse/version.h']
foreach n : ['limits.h', 'types.h', 'flags.h', 'hse.h']
    input_files += meson.project_source_root() / 'include/hse/@0@'.format(n)
endforeach

layout = meson.current_source_dir() / 'doxyfile_layout.xml'
logo = meson.current_source_dir() / 'img/logo.png'
headerfile = meson.current_source_dir() / 'html/headerFile.html'
footerfile = meson.current_source_dir() / 'html/footerFile.html'
cssfile = meson.current_source_dir() / 'html/styleSheetFile.css'
examples = meson.project_source_root() / 'samples'

conf_data = configuration_data({
    'DOXYGEN_INPUT': ' '.join(input_files),
    'DOXYGEN_LAYOUT': layout,
    'DOXYGEN_LOGO': logo,
    'DOXYGEN_HEADER': headerfile,
    'DOXYGEN_FOOTER': footerfile,
    'DOXYGEN_CSS': cssfile,
    'DOXYGEN_EXAMPLES': examples,
    'DOXYGEN_OUTPUT': join_paths(meson.current_build_dir(), 'api'),
    'DOXYGEN_WARN_AS_ERROR': get_option('werror') ? 'YES' : 'NO',
})

doxyfile = configure_file(
    input: 'doxyfile.in',
    output: 'doxyfile',
    configuration: conf_data
)

doxygen = custom_target('doxygen',
    build_by_default: true,
    input: doxyfile,
    command: [doxygen, '@INPUT@'],
    depend_files: [
        logo,
        cssfile,
        headerfile,
        footerfile,
        input_files,
        layout,
        version_h,
    ],
    output: ['api']
)

run_target(
    'doxygen-serve',
    command: [
        bash,
        '-c',
        ' '.join([
            python.full_path(),
            '-m',
            'http.server',
            '--directory',
            '@0@/api/html'.format(meson.current_build_dir()),
            '"${HSE_DOXYGEN_SERVE_PORT:-0}"',
        ])
    ],
    depends: doxygen
)
