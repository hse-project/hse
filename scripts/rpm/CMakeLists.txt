#
# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.

message( STATUS "Configuring ${PROJECT_NAME} rpm..." )

set( CPACK_GENERATOR                "RPM" )
set( CPACK_RPM_COMPONENT_INSTALL    "ON" )

set( CPACK_RPM_PACKAGE_LICENSE      "${CPACK_PACKAGE_LICENSE}" )
set( CPACK_RPM_PACKAGE_RELEASE      "${BUILD_PKG_REL}${BUILD_RTYPE}${BUILD_PKG_DIST}" )
set( CPACK_RPM_PACKAGE_DESCRIPTION  "${CPACK_PACKAGE_DESCRIPTION}" )
set( CPACK_RPM_PACKAGE_ARCHITECTURE "${BUILD_PKG_ARCH}" )
set( CPACK_RPM_PACKAGE_VERSION      "${PROJECT_VERSION}${BUILD_PKG_VQUAL}" )
set( CPACK_RPM_FILE_NAME            "RPM-DEFAULT" )
    
set( CPACK_RPM_PACKAGE_RELOCATABLE  "ON" )
set( CPACK_RPM_RELOCATION_PATHS     /usr /opt /etc )

set( CPACK_RPM_RUNTIME_PACKAGE_NAME      "${CPACK_PACKAGE_NAME}" )
set( CPACK_RPM_RUNTIME_PACKAGE_REQUIRES  "sos >= 3.2" )

set( CPACK_RPM_RUNTIME_PRE_INSTALL_SCRIPT_FILE "${HSE_SCRIPTS_DIR}/rpm/rpm-pre-install.sh" )
set( CPACK_RPM_RUNTIME_POST_INSTALL_SCRIPT_FILE "${HSE_SCRIPTS_DIR}/rpm/rpm-post-install.sh" )
set( CPACK_RPM_RUNTIME_PRE_UNINSTALL_SCRIPT_FILE "${HSE_SCRIPTS_DIR}/rpm/rpm-pre-uninstall.sh" )
set( CPACK_RPM_RUNTIME_POST_UNINSTALL_SCRIPT_FILE "${HSE_SCRIPTS_DIR}/rpm/rpm-post-uninstall.sh" )

set( CPACK_RPM_RUNTIME_PACKAGE_SUMMARY  "${CPACK_PACKAGE_DESCRIPTION_SUMMARY} runtime" )
set( CPACK_RPM_DEVEL_PACKAGE_SUMMARY    "${CPACK_PACKAGE_DESCRIPTION_SUMMARY} devel" )
set( CPACK_RPM_TEST_PACKAGE_SUMMARY     "${CPACK_PACKAGE_DESCRIPTION_SUMMARY} tests" )

# We don't want to claim ownership of these directories, lest there be
# conflicts during RPM install.  If a directory appears in this list,
# it means it might be shared by multiple packages.
#
set( CPACK_RPM_EXCLUDE_FROM_AUTO_FILELIST_ADDITION
  /usr/lib
  /usr/lib/hse
  /usr/lib/hse/modules
  /usr/lib/sysctl.d
  ${HSE_PYTHON_BASE_DIR}
  ${HSE_PYTHON_PKG_DIR}
  ${HSE_PYTHON_SOS_DIR}
  ${HSE_PYTHON_SOS_PLUGINS_DIR}
  /etc
  /lib
  /opt
  /opt/hse
  /opt/hse/bin
  /opt/hse/config
)
