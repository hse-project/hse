include(ExternalProject)

#
# libyaml
#
set(LIBYAML_LIBS ${HSE_STAGE_DIR}/lib/libyaml.a PARENT_SCOPE)

ExternalProject_Add(

    libyaml-ext # Must match rsync destination dir

    PREFIX "${CMAKE_CURRENT_BINARY_DIR}"

    BUILD_IN_SOURCE 1

    DOWNLOAD_COMMAND
        COMMAND /usr/bin/rsync -a --exclude .git ${HSE_SUB_REPOS}/libyaml/ ./libyaml-ext

    UPDATE_COMMAND ""

    CONFIGURE_COMMAND
        COMMAND ./bootstrap
        COMMAND ./configure  --prefix=${HSE_STAGE_DIR}
                             --with-pic
                             --enable-static
                             --disable-shared

    BUILD_COMMAND
        COMMAND make -sj

    INSTALL_COMMAND
        COMMAND make -s install  # install to HSE_STAGE
)

#
# libcurl - a minimal, statically linkable libcurl
#
# To avoid GPL/LGPL tainting, do not compile with
# any of the following features:
#
#    GSS, SSL, TLS NSS or IDNA
#
# See https://curl.haxx.se/legal/licmix.html for details.
#
set(LIBCURL_LIBS ${HSE_STAGE_DIR}/lib/libcurl.a PARENT_SCOPE)

ExternalProject_Add(

    libcurl-ext # Must match rsync destination dir

    BUILD_IN_SOURCE 1

    PREFIX "${CMAKE_CURRENT_BINARY_DIR}"

    DOWNLOAD_COMMAND
        COMMAND /usr/bin/rsync -a --exclude .git ${HSE_SUB_REPOS}/curl/ ./libcurl-ext

    UPDATE_COMMAND ""

    CONFIGURE_COMMAND
        COMMAND autoreconf -i
        COMMAND ./configure --prefix=${HSE_STAGE_DIR}
                            --with-pic
                            --enable-static
                            --disable-shared
                            --without-libssh2
                            --without-zlib
                            --without-libssh2
                            --disable-ipv6
                            --disable-rtsp
                            --disable-ftp
                            --disable-ldap
                            --disable-ldaps
                            --disable-dict
                            --disable-telnet
                            --disable-tftp
                            --disable-pop3
                            --disable-imap
                            --disable-smb
                            --disable-smtp
                            --disable-gopher
                            --disable-manual
                            --without-winidn
                            --without-libidn2
                            --without-libidn
                            --without-ssl
                            --without-gssapi
    BUILD_COMMAND
        COMMAND make -sj

    INSTALL_COMMAND
        COMMAND make -s install  # install to HSE_STAGE
)
