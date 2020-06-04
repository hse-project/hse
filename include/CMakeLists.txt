#
# At the current time, all of the files in hse_kvdb at this level are
# "public," and we're installing all of them as part of our SDK.
#
# The files are being listed individually because we are installing to a 
# directory called "hse" instead of the actual directory name in the tree
# (hse_kvdb).  The INSTALL(DIRECTORY ...) syntax does not support renaming
# directories.
#

INSTALL(
    FILES
        hse/hse.h
        hse/hse_experimental.h
        hse/hse_limits.h
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/hse
    COMPONENT devel
    )
