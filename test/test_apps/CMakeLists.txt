set(HSE_TEST_LABELS test_apps)

# These are visible to all subdirs
include_directories( ${HSE_INCLUDE_DIRS} )
include_directories( ${HSE_UTIL_INCLUDE_DIRS} )
include_directories( ${HSE_3RD_PARTY_INCLUDE_DIRS} )
include_directories( ${HSE_UTIL_UT_GS_INCLUDE_DIRS} )
include_directories( ${MPOOL_UT_GS_INCLUDE_DIRS} )

set( ENABLE_ROCKSDB false )

if( ${YCSB} )
  add_subdirectory( hsejni )
endif()
