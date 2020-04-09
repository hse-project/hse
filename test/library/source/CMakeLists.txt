##############################################################################
#
# HSE Testing Framework Support Library
#
##############################################################################

message( STATUS
  "Configuring test support library in ${CMAKE_CURRENT_SOURCE_DIR}")

if( HSE_UNIT_TEST_FLAG )

    message(STATUS "Configuring mocking support")

    set( COMPONENT_SOURCE_FILES
        ${COMPONENT_SOURCE_FILES}
        allocation.c
        mock_api.c
        mapi_alloc_tester.c
        )

endif()

set( HSE_TEST_SUPPORT_SOURCE_FILES
    ${COMPONENT_SOURCE_FILES}
    mwc_rand.c
    random_buffer.c
    key_generation.c
    )

hse_library(
    NAME hse_test_support
    OUTPUT_NAME hse_test_support
    MODE STATIC
    SRCS
        ${HSE_TEST_SUPPORT_SOURCE_FILES}
    INCLUDES
        ${HSE_UT_FMWK_INCLUDE_DIRS}
        ${HSE_UTIL_INCLUDE_DIRS}
        ${HSE_UT_BASE_INCLUDE_DIRS}
        ${HSE_UT_INCLUDE_DIRS}
        ${HSE_3RD_PARTY_INCLUDE_DIRS}
    LINK_LIBS
        m
)

if( "${CMAKE_BUILD_TYPE}" STREQUAL "Debug" OR
        "${CMAKE_BUILD_TYPE}" STREQUAL "RelWithDebInfo" )
    set( HSE_TEST_SUPPORT_COMPONENT "runtime" )
else()
    set( HSE_TEST_SUPPORT_COMPONENT "test" )
endif()

if( HSE_UNIT_TEST_FLAG )
    # Establish the dependency between the component(s) and the generated code
    hse_ut_mock_generate(
        DEPENDENTS
        hse_test_support-lib
        GENSRC_PREFIX
        # generated headers in HSE_TEST_SUPPORT_GS_UT_INCLUDE_DIRS
        hse_test_support
        SEARCH_DIRS
        ${HSE_TEST_LIB_INCLUDE_DIRS}
        )
    # define the global include directory variable for this component ...
    hse_ut_publish_include_dirs(COMPONENT hse_test_support)
    # ... and add it to include path for userspace target
    include_directories( ${HSE_TEST_SUPPORT_UT_GS_INCLUDE_DIRS} )
endif()

message( STATUS
  "HSE_TEST_SUPPORT_UT_GS_INCLUDE_DIRS == \
${HSE_TEST_SUPPORT_UT_GS_INCLUDE_DIRS}" )

message( STATUS "Configuring unit test library complete" )
