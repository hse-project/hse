
message(STATUS "Configuring hsejni in ${CMAKE_CURRENT_SOURCE_DIR}")

# empty if not HSE_UNIT_TEST_FLAG
include_directories( ${HSE_UT_BASE_INCLUDE_DIRS} )
include_directories( ${HSE_KVDB_UT_GS_INCLUDE_DIRS} )

include_directories(
    ../include
    ../../se_lib/
    /etc/alternatives/java_sdk/include/
    /etc/alternatives/java_sdk/include/linux/
)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DCOMPNAME=\\\"hsejni\\\"" )

set(CMAKE_SHARED_LINKER_FLAGS
    "${CMAKE_SHARED_LINKER_FLAGS} -L ${MPOOL_LIB_DIR} -L ${BLKID_LIB_DIR}")

set(MY_LINK_LIBS
        hse_kvdb-lib
)

set(COMPONENT_SOURCE_FILES
    hsejni.c
    hse_jni_util.c
)
  
add_library(hsejni_c SHARED
  ${COMPONENT_SOURCE_FILES}
)

target_link_libraries(
    hsejni_c
        ${MY_LINK_LIBS}
        ${HSE_USER_MPOOL_LINK_LIBS}
        microhttpd
        ${LIBYAML_LIBS}
        hse_jni_headers
)

#
# For if/when we split this off from the main runtime package.
#
#install(TARGETS hsejni_c DESTINATION ${CMAKE_INSTALL_LIBDIR} COMPONENT java)

install(TARGETS hsejni_c DESTINATION ${CMAKE_INSTALL_LIBDIR} COMPONENT runtime)
