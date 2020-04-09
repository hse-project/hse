##############################################################################
#
# CLI Build/Package Definitions
#
##############################################################################

message(STATUS "Configuring cli ${CMAKE_CURRENT_SOURCE_DIR}")

set( CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DCOMPNAME=\\\"CLI\\\"" )

hse_executable(
    NAME hse
    COMPONENT runtime
    SRCS
        hse_cli.c
        cli_util.c
    INCLUDES
        ${HSE_INCLUDE_DIRS}
        ${HSE_UTIL_INCLUDE_DIRS}
        ${HSE_3RD_PARTY_INCLUDE_DIRS}
        ${MPOOL_INCLUDE_DIR}
    DEPS
        libcurl-ext
        libyaml-ext
    LINK_DIRS
        ${MPOOL_LIB_DIR}
    LINK_LIBS
        ${LIBCURL_LIBS}
        ${LIBYAML_LIBS}
        hse_kvdb_static-lib
    )
