#
# The library subdirectory is added explicitly by the next layer up because of
# an ordering dependency. The "test_apps" subdirectory contains software that
# generates executables that leverage the elements of hse/src. However, in
# order to describe the dependency of hse_platform-lib on hse_test_support-lib
# within components/platform, CMake must know about the hse_test_support-lib
# library before it reaches hse/src/util. Therefore, CMake must process the
# hse/test/library area before hse/src/util.
#

add_subdirectory( test_apps )
