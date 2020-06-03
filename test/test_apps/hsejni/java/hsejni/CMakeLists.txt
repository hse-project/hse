find_package(Java REQUIRED COMPONENTS Runtime Development)
find_package(JNI REQUIRED)
include (UseJava)

set(CMAKE_JNI_TARGET TRUE)

add_jar(hsejni
  src/org/micron/hse/API.java
  src/org/micron/hse/HSEEOFException.java
  src/org/micron/hse/HSEGenException.java
  OUTPUT_DIR ${CMAKE_CURRENT_BINARY_DIR}
  )

ADD_CUSTOM_TARGET(
  hsejni_API.h ALL
  DEPENDS ${HSE_STAGE_DIR}/include/hsejni_API.h)

#COMMAND ${Java_JAVAH_EXECUTABLE} -cp hsejni.jar  -o ${HSE_STAGE_DIR}/include/hsejni_API.h  org.micron.hse.API
#OUTPUT  ${HSE_STAGE_DIR}/include/hsejni_API.h
# Command sequence for: src -> real_kmod_file
ADD_CUSTOM_COMMAND(
  OUTPUT  ${HSE_STAGE_DIR}/include/hsejni_API.h
  COMMAND ${Java_JAVAC_EXECUTABLE} -cp hsejni.jar -h ${HSE_STAGE_DIR}/include ${PROJECT_SOURCE_DIR}/test/test_apps/hsejni/java/hsejni/src/org/micron/hse/API.java
  COMMAND cp ${HSE_STAGE_DIR}/include/org_micron_hse_API.h ${HSE_STAGE_DIR}/include/hsejni_API.h
  DEPENDS hsejni
  VERBATIM)

#
# For if/when we split this off from the main runtime package.
#
#install_jar(hsejni DESTINATION share/hse/jni COMPONENT java)

install_jar(hsejni DESTINATION share/hse/jni COMPONENT runtime)
