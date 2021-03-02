cmake_minimum_required(VERSION 2.8)

if("${CMAKE_VERSION}" VERSION_GREATER 3.0.0)
    cmake_policy(SET CMP0042 NEW)
endif()

project("hdr_histogram")

# Follow all steps below in order to calculate new ABI version when updating the library
# NOTE: THIS IS UNRELATED to the actual project version
#
# 1. If the library source code has changed at all since the last update, then increment revision
# 2. If any interfaces have been added, removed, or changed since the last update, increment current and set revision to 0.
# 3. If any interfaces have been added since the last public release, then increment age.
# 4. If any interfaces have been removed since the last public release, then set age to 0.

set(HDR_SOVERSION_CURRENT   5)
set(HDR_SOVERSION_AGE       0)
set(HDR_SOVERSION_REVISION  0)

set(HDR_VERSION ${HDR_SOVERSION_CURRENT}.${HDR_SOVERSION_AGE}.${HDR_SOVERSION_REVISION})
set(HDR_SOVERSION ${HDR_SOVERSION_CURRENT})

include(GNUInstallDirs)

ENABLE_TESTING()

if(UNIX)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wno-unknown-pragmas -Wextra -Wshadow -Winit-self -Wmissing-prototypes -Wpedantic -D_GNU_SOURCE -std=gnu89 -fPIC")
    set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -O0 -g")
    set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -O3 -g")
endif()

if(WIN32)
    find_package (zlib REQUIRED)
else()
    find_package (ZLIB REQUIRED)
endif()

include_directories("${CMAKE_CURRENT_SOURCE_DIR}/src")

add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/src")

option(HDR_HISTOGRAM_BUILD_PROGRAMS "Build tests and examples" ON)
if(HDR_HISTOGRAM_BUILD_PROGRAMS)
  add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/test")
  add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/examples")
endif(HDR_HISTOGRAM_BUILD_PROGRAMS)

SET(CPACK_GENERATOR "TGZ")
SET(CPACK_PACKAGE_VERSION "0.9.12")

INCLUDE(CPack)
