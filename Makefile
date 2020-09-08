#
# Top-level HSE Makefile.
#

define HELP_TEXT

HSE Makefile Help
-----------------

Primary Targets:

  all       -- Build binaries, libraries, unit tests, etc.
  clean     -- Delete most build outputs (saves external repos).
  config    -- Create build output directory and run cmake config.
  distclean -- Delete all build outputs (i.e., start over).
  help      -- Print this message.
  package   -- Build "all" and generate deb/rpm packages
  rebuild   -- Alias for 'distclean all'.
  test      -- Run unit tests.

Target Modiiers:

  asan      -- Enable address sanity checking
  debug     -- Create a debug build
  optdebug  -- Create a debug build with -Og
  release   -- Create a release build
  relassert -- Create a release build with assert enabled
  ubsan     -- Enable undefined behavior checking

Configuration Variables:

  These configuration variables can be set on the command line or customized
  via included makefiles. To use the latter mechanism, set the environment
  variable HSE_MAKE_PRE_INCLUDE to refer to a GNU Make syntax file that will
  be inlined by this makefile. You can also define the environment variable
  HSE_MAKE_POST_INCLUDE to refer to a GNU Make syntax file that will be
  inlined at the bottom of this makefile. That mechanism can be used to add
  new targets that may be useful in a particular development workflow. (see
  "Customization" below).

    BUILD_DIR         -- The top-level build output directory
    BUILD_NUMBER      -- Build job number (as set by Jenkins)
    BUILD_PKG_TYPE    -- Specify package type (rpm or deb)
    BUILD_PKG_VENDOR  -- Specify the vendor/maintainer tag in the package
    DEPGRAPH          -- Set to "--graphviz=<filename_prefix>" to generate
                         graphviz dependency graph files

  Defaults (not all are customizable):

    BUILD_DIR          $(BUILD_DIR)
    BUILD_NODE         $(BUILD_NODE)
    BUILD_NUMBER       $(BUILD_NUMBER)
    BUILD_TYPE         $(BUILD_TYPE)
    BUILD_STYPE        $(BUILD_STYPE)
    BUILD_CFLAGS       $(BUILD_CFLAGS)
    BUILD_CDEFS        $(BUILD_CDEFS)
    BUILD_PKG_ARCH     ${BUILD_PKG_ARCH}
    BUILD_PKG_DIR      ${BUILD_PKG_DIR}
    BUILD_PKG_DIST     ${BUILD_PKG_DIST}
    BUILD_PKG_REL      ${BUILD_PKG_REL}
    BUILD_PKG_SHA      ${BUILD_PKG_SHA}
    BUILD_PKG_TAG      ${BUILD_PKG_TAG}
    BUILD_PKG_TYPE     ${BUILD_PKG_TYPE}
    BUILD_PKG_VERSION  ${BUILD_PKG_VERSION}
    BUILD_PKG_VENDOR   ${BUILD_PKG_VENDOR}
    BUILD_PKG_VQUAL    ${BUILD_PKG_VQUAL}
    CMAKE_BUILD_TYPE   ${CMAKE_BUILD_TYPE}

Customization:

  There are two main ways that the behavior of this makefile can be customized,
  (1) pointing the build to an mpool tree that is not installed, and (2) adding
  custom targets. The latter is primarily useful when running test tools that
  are not part of the standard gcc toolchain. The former is useful for developers
  that may have a checked out and built copy of the mpool and mpool-kmod trees
  but for whatever reason those are not installed.

  As an example, suppose the user jane doe wishes to build hse against an mpool
  repo in her home directory, executing the build on a machine named "host".
  She would then put the following lines in a file that is named by an environment
  variable HSE_MAKE_PRE_INCLUDE:

      MPOOL_INCLUDE_DIR := /home/jdoe/mpool/include
      MPOOL_LIB_DIR := /home/jdoe/mpool/builds/host/rpm/release/src/mpool
      BLKID_LIB_DIR := /home/jdoe/mpool/builds/host/rpm/release/ext_install/lib

  Compilation of the HSE code will then take place against the referenced mpool.
  In order to run the unit tests, she would also have to set LD_LIBRARY_PATH so
  that the unit tests could resolve those symbols - even though the real mpool
  entry points would not be called. For example:

      export COMMON=/home/jdoe/mpool/builds/host/rpm/release
      export LD_LIBRARY_PATH=${COMMON}/src/mpool:${COMMON}/ext_install/lib


Examples:

  Rebuild:

    make rebuild
    make debug rebuild

  Create packages:

    make package

  Using ASAN/LSAN:

    fc25 and newer:

	sudo dnf install libasan libubsan

    rhel 7 vintage:

	sudo yum install devtoolset-7
        sudo yum install devtoolset-7-libasan-devel devtoolset-7-libubsan-devel
        . /opt/rh/devtoolset-7/enable

    export LSAN_OPTIONS=suppressions=scripts/dev/lsan.sup,print_suppressions=0,detect_leaks=true
    make relassert config asan

  Using UBASAN:

    See asan/lsan (above) for setup instructions

    export UBSAN_OPTIONS=suppressions=scripts/dev/ubsan.sup,print_stacktrace=1
    make relassert config ubsan

endef


.DEFAULT_GOAL := all
.DELETE_ON_ERROR:
.NOTPARALLEL:


# Edit the package VERSION and QUALifier when we cut a release branch or tag:
BUILD_PKG_VERSION := 1.9.0
BUILD_PKG_VQUAL := '~dev'

BUILD_PKG_VENDOR ?= "Micron Technology, Inc."

BUILD_PKG_SHA := $(shell test -d ".git" && git rev-parse HEAD 2>/dev/null)

BUILD_PKG_TAG := $(shell test -d ".git" && \
	git describe --always --long --tags --dirty --abbrev=10 2>/dev/null)

ifeq (${BUILD_PKG_TAG},)
BUILD_PKG_TAG := ${BUILD_PKG_VERSION}
BUILD_PKG_REL := 0
BUILD_PKG_SHA := 0
else
BUILD_PKG_REL := $(shell echo ${BUILD_PKG_TAG} | \
	sed -En 's/.*-([0-9]+)-[a-z0-9]{7,}(-dirty){0,1}$$/\1/p')
BUILD_PKG_VQUAL := $(shell echo ${BUILD_PKG_TAG} | \
	sed -En 's/.*-([^-]+)-[0-9]+-[a-z0-9]{7,}(-dirty){0,1}$$/~\1/p')
endif

ifneq ($(shell egrep -i 'id=(ubuntu|debian)' /etc/os-release),)
BUILD_PKG_TYPE ?= deb
BUILD_PKG_ARCH ?= $(shell dpkg-architecture -q DEB_HOST_ARCH)
BUILD_PKG_DIST :=
else
BUILD_PKG_TYPE ?= rpm
BUILD_PKG_ARCH ?= $(shell uname -m)
BUILD_PKG_DIST := $(shell rpm --eval '%{?dist}')
endif

#ifeq ($(wildcard scripts/${BUILD_PKG_TYPE}/CMakeLists.txt),)
#$(error "Unable to create a ${BUILD_PKG_TYPE} package, try rpm or deb")
#endif


# SRC_DIR is set to the top of the this source tree.
SRC_DIR := $(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))

################################################################
#
# Config defaults.
#
################################################################
HSE_UNIT_TEST_FLAG := FALSE

ifeq ($(findstring release,$(MAKECMDGOALS)),release)
	BUILD_TYPE := release
	BUILD_STYPE := r
	BUILD_CFLAGS := -O2
	BUILD_CDEFS := -DHSE_BUILD_RELEASE
	BUILD_CDEFS += -DHSE_LOG_PRI_DEFAULT=5
	CMAKE_BUILD_TYPE := Release
else ifeq ($(findstring relwithdebug,$(MAKECMDGOALS)),relwithdebug)
	BUILD_TYPE := relwithdebug
	BUILD_STYPE := i
	BUILD_CFLAGS := -O2
	BUILD_CDEFS := -DHSE_BUILD_RELEASE
	BUILD_CDEFS += -DHSE_LOG_PRI_DEFAULT=5
	CMAKE_BUILD_TYPE := RelWithDebInfo
else ifeq ($(findstring relassert,$(MAKECMDGOALS)),relassert)
	BUILD_TYPE := relassert
	BUILD_STYPE := a
	BUILD_CFLAGS := -O2
	BUILD_CDEFS := -DHSE_BUILD_RELASSERT -D_FORTIFY_SOURCE=2
	BUILD_CDEFS += -DHSE_LOG_PRI_DEFAULT=5
	CMAKE_BUILD_TYPE := Debug
else ifeq ($(findstring optdebug,$(MAKECMDGOALS)),optdebug)
	BUILD_TYPE := optdebug
	BUILD_STYPE := o
	BUILD_CFLAGS := -Og
	BUILD_CDEFS := -DHSE_BUILD_DEBUG
	BUILD_CDEFS += -DHSE_LOG_PRI_DEFAULT=7
	CMAKE_BUILD_TYPE := Debug
else ifeq ($(findstring debug,$(MAKECMDGOALS)),debug)
	BUILD_TYPE := debug
	BUILD_STYPE := d
	BUILD_CFLAGS := -fstack-protector-all
	BUILD_CDEFS := -DHSE_BUILD_DEBUG -DDEBUG_RCU
	BUILD_CDEFS += -DHSE_LOG_PRI_DEFAULT=7
	CMAKE_BUILD_TYPE := Debug
	HSE_UNIT_TEST_FLAG := TRUE
else
	BUILD_TYPE := release
	BUILD_STYPE := r
	BUILD_CFLAGS := -O2
	BUILD_CDEFS := -DHSE_BUILD_RELEASE
	BUILD_CDEFS += -DHSE_LOG_PRI_DEFAULT=5
	CMAKE_BUILD_TYPE := Release
endif

BUILD_DIR     ?= ${SRC_DIR}/builds
BUILD_NODE    ?= $(shell uname -n)
BUILD_PKG_DIR ?= ${BUILD_DIR}/${BUILD_NODE}/${BUILD_PKG_TYPE}/${BUILD_TYPE}
UBSAN         ?= 0
ASAN          ?= 0
BUILD_NUMBER  ?= 0

MPOOL_INCLUDE_DIR ?= /usr/include

# The variables DEV_MPOOL_LIB_DIR and DEV_BLKID_LIB_DIR are set to true if the
# developer is explicitly pointing the build to particular built images of the
# mpool and blkid libraries

ifeq (${MPOOL_LIB_DIR},)
	DEV_MPOOL_LIB_DIR := true
else
	DEV_MPOOL_LIB_DIR := false
endif

ifeq (${BLKID_LIB_DIR},)
	DEV_BLKID_LIB_DIR := true
else
	DEV_BLKID_LIB_DIR := false
endif

ifeq (${BUILD_PKG_TYPE},deb)
	MPOOL_LIB_DIR ?= /usr/lib/x86_64-linux-gnu
	BLKID_LIB_DIR ?= /usr/lib/x86_64-linux-gnu/mpool
else
	MPOOL_LIB_DIR ?= /usr/lib64
	BLKID_LIB_DIR ?= /usr/lib64/mpool
endif

ifeq ($(filter ubsan,$(MAKECMDGOALS)),ubsan)
UBSAN := 1
endif

ifeq ($(filter asan,$(MAKECMDGOALS)),asan)
ASAN := 1
endif

ifneq ($(origin HSE_MAKE_PRE_INCLUDE),undefined)
    # See "Customization" above
    -include $(HSE_MAKE_PRE_INCLUDE)
endif

################################################################
# Git and external repos
################################################################

libyaml_repo := libyaml
${libyaml_repo}_tag := 0.1.7
${libyaml_repo}_url := https://github.com/yaml/libyaml

curl_repo := curl
${curl_repo}_tag := curl-7_50_3
${curl_repo}_url := https://github.com/curl/curl

SUBREPO_PATH_LIST := sub/$(curl_repo) sub/$(libyaml_repo)

PERL_CMAKE_NOISE_FILTER := \
    perl -e '$$|=1;\
        while (<>) {\
            next if m/(Entering|Leaving) directory/;\
            next if m/Not a git repository/;\
            next if m/GIT_DISCOVERY_ACROSS_FILESYSTEM/;\
            next if m/^\[..\d%\]/;\
            next if m/cmake_progress/;\
            print;\
        }'

ifeq ($(CTEST_LABEL),)
CTEST_ULABEL = -L user_unit
else
CTEST_ULABEL = -L "$(CTEST_LABEL)"
endif

RUN_CTEST = export HSE_BUILD_DIR="$(BUILD_PKG_DIR)"; set -e -u; cd "$(BUILD_PKG_DIR)"; ctest --output-on-failure $(CTEST_FLAGS)

RUN_CTEST_U = $(RUN_CTEST) $(CTEST_ULABEL)


define config-gen =
	( echo '# Note: When a variable is set multiple times in this file' ;\
	  echo '#       it is the *first* setting that sticks!' ;\
	  echo ;\
	  echo 'Set( BUILD_NUMBER           "$(BUILD_NUMBER)" CACHE STRING "" )' ;\
	  echo 'Set( BUILD_TYPE             "$(BUILD_TYPE)" CACHE STRING "" )' ;\
	  echo 'Set( BUILD_CFLAGS           "$(BUILD_CFLAGS)" CACHE STRING "" )' ;\
	  echo 'Set( BUILD_CDEFS            "$(BUILD_CDEFS)" CACHE STRING "" )' ;\
	  echo 'Set( BUILD_STYPE            "$(BUILD_STYPE)" CACHE STRING "" )' ;\
	  echo 'Set( BUILD_PKG_ARCH         "$(BUILD_PKG_ARCH)" CACHE STRING "" )' ;\
	  echo 'Set( BUILD_PKG_DIST         "$(BUILD_PKG_DIST)" CACHE STRING "" )' ;\
	  echo 'Set( BUILD_PKG_REL          "$(BUILD_PKG_REL)" CACHE STRING "" )' ;\
	  echo 'Set( BUILD_PKG_SHA          "$(BUILD_PKG_SHA)" CACHE STRING "" )' ;\
	  echo 'Set( BUILD_PKG_TAG          "$(BUILD_PKG_TAG)" CACHE STRING "" )' ;\
	  echo 'Set( BUILD_PKG_TYPE         "$(BUILD_PKG_TYPE)" CACHE STRING "" )' ;\
	  echo 'Set( BUILD_PKG_VERSION      "$(BUILD_PKG_VERSION)" CACHE STRING "" )' ;\
	  echo 'Set( BUILD_PKG_VENDOR       "'$(BUILD_PKG_VENDOR)'" CACHE STRING "" )' ;\
	  echo 'Set( BUILD_PKG_VQUAL        "$(BUILD_PKG_VQUAL)" CACHE STRING "" )' ;\
	  echo 'Set( CMAKE_BUILD_TYPE       "$(CMAKE_BUILD_TYPE)" CACHE STRING "" )' ;\
	  echo 'Set( HSE_UNIT_TEST_FLAG     "${HSE_UNIT_TEST_FLAG}" CACHE STRING "" )' ;\
	  echo 'Set( UBSAN                  "$(UBSAN)" CACHE BOOL "" )' ;\
	  echo 'Set( ASAN                   "$(ASAN)" CACHE BOOL "" )' ;\
	  echo 'set( MPOOL_INCLUDE_DIR      "$(MPOOL_INCLUDE_DIR)" CACHE STRING "" FORCE)' ;\
	  echo 'set( DEV_MPOOL_LIB_DIR      "$(DEV_MPOOL_LIB_DIR)" CACHE STRING "" FORCE)' ;\
	  echo 'set( MPOOL_LIB_DIR          "$(MPOOL_LIB_DIR)" CACHE STRING "" FORCE)' ;\
	  echo 'set( DEV_BLKID_LIB_DIR      "$(DEV_BLKID_LIB_DIR)" CACHE STRING "" FORCE)' ;\
	  echo 'set( BLKID_LIB_DIR          "$(BLKID_LIB_DIR)" CACHE STRING "" FORCE)' ;\
  )
endef


# If MAKECMDGOALS contains no goals other than any combination of
# BTYPES then make the given goals depend on the default goal.
#
BTYPES := debug release relwithdebug relassert optdebug asan ubsan
BTYPES := $(filter ${BTYPES},${MAKECMDGOALS})

ifeq ($(filter-out ${BTYPES},${MAKECMDGOALS}),)
BTYPESDEP := ${.DEFAULT_GOAL}
endif


# Delete the cmake config file if it has changed.
#
CONFIG = $(BUILD_PKG_DIR)/config.cmake

ifeq ($(filter config-preview help print-% printq-% test testp load unload,$(MAKECMDGOALS)),)
$(shell $(config-gen) | cmp -s - ${CONFIG} || rm -f ${CONFIG})
endif


.PHONY: all allv allq allqv allvq ${BTYPES}
.PHONY: clean config config-preview distclean
.PHONY: help install maintainer-clean package rebuild
.PHONY: test testp testv showtests showutests


# Goals in mostly alphabetical order.
#
all: config
	@$(MAKE) --no-print-directory -C "$(BUILD_PKG_DIR)" $(MF)

allv: config
	$(MAKE) -C "$(BUILD_PKG_DIR)" VERBOSE=1 $(MF)

allq: config
	$(MAKE) -C "$(BUILD_PKG_DIR)" $(MF) 2>&1 | $(PERL_CMAKE_NOISE_FILTER)

allqv allvq: config
	$(MAKE) -C "$(BUILD_PKG_DIR)" VERBOSE=1 $(MF) 2>&1 | $(PERL_CMAKE_NOISE_FILTER)

ifneq (${BTYPES},)
${BTYPES}: ${BTYPESDEP}
	@true
endif

clean:
	for d in $(patsubst %,${BUILD_PKG_DIR}/%,src cli test samples) ; do \
		if test -f "$$d/Makefile"; then \
			$(MAKE) --no-print-directory -C "$$d" clean ;\
		fi ;\
	done
	find ${BUILD_PKG_DIR} -name \*.${BUILD_PKG_TYPE} -exec rm -f {} \;

config-preview:
ifneq ($(wildcard ${CONFIG}),)
	@sed -En 's/^[^#]*\((.*)CACHE.*/\1/p' ${CONFIG}
endif
	@true

${CONFIG}: MAKEFLAGS += --no-print-directory
${CONFIG}: Makefile CMakeLists.txt $(wildcard scripts/${BUILD_PKG_TYPE}/CMakeLists.txt)
	mkdir -p $(@D)
	rm -f $(@D)/CMakeCache.txt
	@$(config-gen) > $@.tmp
	cd $(@D) && cmake $(DEPGRAPH) $(CMAKE_FLAGS) -C $@.tmp $(SRC_DIR)
	$(MAKE) -C $(@D) clean
	mv $@.tmp $@

config: $(SUBREPO_PATH_LIST) $(CONFIG)

distclean:
	rm -rf ${BUILD_PKG_DIR} *.${BUILD_PKG_TYPE}

help:
	$(info $(HELP_TEXT))
	@true

install: MAKEFLAGS += --no-print-directory
install: config
	@$(MAKE) -C "$(BUILD_PKG_DIR)" install

maintainer-clean: distclean
	rm -rf ${BUILD_DIR} *.rpm *.deb
ifneq ($(wildcard ${SUBREPO_PATH_LIST}),)
	rm -rf ${SUBREPO_PATH_LIST}
endif

package: MAKEFLAGS += --no-print-directory
package: config
	-find ${BUILD_PKG_DIR} -name \*.${BUILD_PKG_TYPE} -exec rm -f {} \;
	$(MAKE) -C ${BUILD_PKG_DIR} package

rebuild: distclean all

showtests:
	$(RUN_CTEST) -V -N

showutests:
	$(RUN_CTEST_U) -V -N

ifneq (${SUBREPO_PATH_LIST},)
${SUBREPO_PATH_LIST}:
	rm -rf $@ $@.tmp
	git clone -b $($(@F)_tag) --depth 1 $($(@F)_url).git $@.tmp
	mv $@.tmp $@
endif

test:
	$(RUN_CTEST_U)

testp:
	$(RUN_CTEST_U) -j$(shell nproc || echo 10)

testv:
	HSE_UT_VERBOSE=1 HSE_UT_LOGPRI=7 $(RUN_CTEST_U) -V

# Do not remove these print targets.  They are used by automation to get
# the output build directory (which can vary based on buildtype, and
# settings of BUILD_DIR in HSE_MAKE_PRE_INCLUDE).
# Example use:
#
#  d=$(make -s --no-print-directory printq-BUILD_DIR)
#  rpm -i $d/*.rpm
#					
printq-%:
	$(info $($*))
	@true
print-%:
	$(info $*="$($*)")
	@true

ifneq ($(origin HSE_MAKE_POST_INCLUDE),undefined)
    # See "Customization" above
    -include $(HSE_MAKE_POST_INCLUDE)
endif


# BUILD_DIR may not be ., ./, ./., ./.., /, /., /.., nor empty,
# nor may it contain any whitespace.
#
ifeq ($(abspath ${BUILD_DIR}),)
$(error BUILD_DIR may not be [nil])
else ifeq ($(abspath ${BUILD_DIR}),/)
$(error BUILD_DIR may not be [/])
else ifeq ($(abspath ${BUILD_DIR}),$(abspath ${CURDIR}))
$(error BUILD_DIR may not be [${CURDIR}])
else ifeq ($(abspath ${BUILD_DIR}),$(abspath ${CURDIR}/..))
$(error BUILD_DIR may not be [${CURDIR}/..])
else ifneq ($(words ${BUILD_DIR}),1)
$(error BUILD_DIR may not contain whitespace)
endif
