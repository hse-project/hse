project(
    'curl',
    ['c'],
    version: '7.58.0',
    meson_version: '>=0.57.0',
)

extern = import('unstable_external_project')

run_command('buildconf', check: true)

configure_options = [
    '--enable-http',
    '--enable-unix-sockets',
    '--enable-symbol-hiding',
    '--disable-ares',
    '--disable-largefile',
    '--disable-ftp',
    '--disable-file',
    '--disable-ldap',
    '--disable-ldaps',
    '--disable-rtsp',
    '--disable-proxy',
    '--disable-dict',
    '--disable-telnet',
    '--disable-tftp',
    '--disable-pop3',
    '--disable-imap',
    '--disable-smb',
    '--disable-smtp',
    '--disable-gopher',
    '--disable-manual',
    '--disable-ipv6',
    '--disable-sspi',
    '--disable-nltm-wb',
    '--disable-tls-srp',
    '--disable-cookies',
    '--without-brotli',
    '--without-winssl',
    '--without-darwinssl',
    '--without-ssl',
    '--without-gnutls',
    '--without-polarssl',
    '--without-mbedtls',
    '--without-cyassl',
    '--without-wolfssl',
    '--without-nss',
    '--without-axtls',
    '--without-ca-bundle',
    '--without-ca-fallback',
    '--without-librtmp',
    '--without-winidn',
    '--without-libidn2',
    '--without-nghttp2',
    '--without-zsh-functions-dir',
    '--without-zlib',
]

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
)

libcurl_dep = proj.dependency('curl')
