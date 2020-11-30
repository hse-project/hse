project(
	'curl',
	['c'],
	version: '7.61.1',
	meson_version: '>=0.57',
)

extern = import('unstable_external_project')

run_command('buildconf')

proj = extern.add_project(
	'configure',
	configure_options: [
		'--enable-http',
		'--enable-unix-sockets',
		'--enable-symbol-hiding',
		'--disable-static',
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
	],
)

libcurl_dep = proj.dependency('curl')
