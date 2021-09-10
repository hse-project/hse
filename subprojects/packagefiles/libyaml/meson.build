project(
    'libyaml',
    ['c'],
    version: '0.1.7',
    meson_version: '>=0.57.0',
)

cc = meson.get_compiler('c')

c_flags = []

if get_option('werror')
    c_flags += '-Werror'
endif

if get_option('warning_level') == '0'
    if cc.get_id() == 'gcc'
        c_flags += '-w'
    elif cc.get_id() == 'clang'
        c_flags += '-Wno-everything'
    elif
        error('Unable to translate "warning_level" for your compiler')
    endif
else
    error('Unable to translate "warning_level" for your compiler')
endif

extern = import('unstable_external_project')

run_command('bootstrap', check: true)

configure_options = []

if get_option('default_library') == 'shared'
    configure_options += '--enable-shared'
    configure_options += '--disable-static'
elif get_option('default_library') == 'static'
    configure_options += '--disable-shared'
    configure_options += '--enable-static'
elif get_option('default_library') == 'both'
    configure_options += '--enable-shared'
    configure_options += '--enable-static'
endif

if get_option('b_staticpic')
    configure_options += '--with-pic'
endif

proj = extern.add_project(
    'configure',
    configure_options: configure_options,
    env: environment({
        'CFLAGS': ' '.join(c_flags),
    })
)

libyaml_dep = proj.dependency('yaml')

meson.override_dependency('yaml-0.1', libyaml_dep)
