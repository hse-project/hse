find_package(Java REQUIRED COMPONENTS Runtime Development)
find_package(JNI REQUIRED)
include (UseJava)

set(CMAKE_JNI_TARGET TRUE)

add_jar(hsejni
  src/org/micron/hse/API.java
  src/org/micron/hse/HSEEOFException.java
  src/org/micron/hse/HSEGenException.java
  OUTPUT_DIR ${CMAKE_CURRENT_BINARY_DIR}
  GENERATE_NATIVE_HEADERS hse_jni_headers DESTINATION ${HSE_STAGE_DIR}/include/
  )

#
# For if/when we split this off from the main runtime package.
#
#install_jar(hsejni DESTINATION share/hse/jni COMPONENT java)

install_jar(hsejni DESTINATION share/hse/jni COMPONENT runtime)
