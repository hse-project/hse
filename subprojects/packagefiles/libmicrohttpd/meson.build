project(
    'libmicrohttpd',
    ['c'],
    version: '0.9.59',
    meson_version: '>=0.57.0',
)

extern = import('unstable_external_project')

configure_options = [
    '--disable-doc',
    '--disable-examples',
    '--disable-curl',
    '--disable-largefile',
    '--disable-sendfile',
    '--disable-bauth',
    '--disable-dauth',
    '--disable-httpupgrade',
    '--disable-https',
    '--without-gnutls',
]

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

libmicrohttpd_dep = proj.dependency('microhttpd')
