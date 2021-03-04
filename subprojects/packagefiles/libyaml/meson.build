project(
    'libyaml',
    ['c'],
    version: '0.1.7',
    meson_version: '>=0.57.0',
)

extern = import('unstable_external_project')

run_command('bootstrap', check: true)

configure_options = []

if get_option('default_library') == 'shared'
    configure_options += '--enable-shared'
    configure_options += '--disable-static'
elif get_option('default_library') == 'static'
    configure_options += '--disable-shared'
    configure_options += '--enable-static'
    configure_options += '--with-pic'
elif get_option('default_library') == 'both'
    configure_options += '--enable-shared'
    configure_options += '--enable-static'
    configure_options += '--with-pic'
endif

proj = extern.add_project(
    'configure',
    configure_options: configure_options,
)

libyaml_dep = proj.dependency('yaml')
