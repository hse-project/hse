# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# SPDX-FileCopyrightText: Copyright 2020 Micron Technology, Inc.

project(
    'curl',
    'c',
    version: '7.85.0',
    meson_version: '>=0.57.0'
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
    else
        error('Unable to translate "warning_level" for your compiler')
    endif
else
    error('Unable to translate "warning_level" for your compiler')
endif

extern = import('unstable-external_project')

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
    '--disable-mqtt',
    '--disable-manual',
    '--disable-ipv6',
    '--disable-sspi',
    '--disable-tls-srp',
    '--disable-crypto-auth',
    '--disable-ntlm',
    '--disable-ntlm-wb',
    '--disable-tls-srp',
    '--disable-cookies',
    '--disable-http-auth',
    '--disable-doh',
    '--disable-netrc',
    '--disable-dnsshuffle',
    '--disable-alt-svc',
    '--disable-headers-api',
    '--disable-hsts',
    '--without-brotli',
    '--without-ssl',
    '--without-hyper',
    '--without-zlib',
    '--without-zstd',
    '--without-nss',
    '--without-ca-bundle',
    '--without-ca-fallback',
    '--without-libpsl',
    '--without-libgsasl',
    '--without-librtmp',
    '--without-winidn',
    '--without-libidn2',
    '--without-nghttp2',
    '--without-ngtcp2',
    '--without-nghttp3',
    '--without-quiche',
    '--without-msh3',
    '--without-zsh-functions-dir',
    '--without-fish-functions-dir',
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
    env: environment({
        'CFLAGS': ' '.join(c_flags),
    })
)

libcurl_dep = proj.dependency('curl')

meson.override_dependency('libcurl', libcurl_dep)
