include_directories( ${HSE_UTIL_INCLUDE_DIRS} )
include_directories( ${HSE_3RD_PARTY_INCLUDE_DIRS} )
include_directories( ${HSE_TEST_INCLUDE_DIRS}  )

set( kbuild_cflags "${kbuild_cflags} -DCOMPNAME=\\\"hsejni\\\"" )
set( CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DCOMPNAME=\\\"hsejni\\\"" )

include_directories( ${HSE_UT_BASE_INCLUDE_DIRS} )
include_directories(
    ../include)

# HSE_REVISIT - this test fails on el7
if( HSE_UNIT_TEST_FLAG )
if ( "${HSE_DISTRO_PREFIX}" STREQUAL "fc" )
hse_unit_test(
      NAME hsejni_parse_test
      SRCS hsejni_parse_test.c
      LINK_DIRS
        ${MPOOL_LIB_DIR}
      LINK_LIBS
        hse_test_support-lib
        hsejni_c)
endif()
endif()
