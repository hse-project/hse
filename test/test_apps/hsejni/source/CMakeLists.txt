# empty if not HSE_UNIT_TEST_FLAG
if( ${HSE_BUILD_USER} )
include_directories( ${HSE_UT_BASE_INCLUDE_DIRS} )
include_directories( ${HSE_KVDB_UT_GS_INCLUDE_DIRS} )

# TODO: Quick fix to get compiling on ubuntu...
#
if( "${BUILD_PKG_TYPE}" STREQUAL "deb" )
	include_directories( "/usr/lib/jvm/java-8-openjdk-amd64/include" )
	include_directories( "/usr/lib/jvm/java-8-openjdk-amd64/include/linux" )
endif()

include_directories(
    ../include
    ../../se_lib/
    /etc/alternatives/java_sdk/include/
    /etc/alternatives/java_sdk/include/linux/
)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DCOMPNAME=\\\"hsejni\\\"" )

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

add_dependencies(hsejni_c hsejni hsejni_API.h)

target_link_libraries(
    hsejni_c
        ${MY_LINK_LIBS}
        ${HSE_USER_MPOOL_LINK_LIBS}
        microhttpd
        ${LIBYAML_LIBS}
)

#
# For if/when we split this off from the main runtime package.
#
#install(TARGETS hsejni_c DESTINATION ${CMAKE_INSTALL_LIBDIR} COMPONENT java)

install(TARGETS hsejni_c DESTINATION ${CMAKE_INSTALL_LIBDIR} COMPONENT runtime)

endif() # ${HSE_BUILD_USER}
