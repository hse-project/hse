#
# Top-level HSE Makefile.
#

define HELP_TEXT

HSE Makefile Help
-----------------

Primary Targets:

    scrub     -- Delete all build outputs (i.e., start over).
    clean     -- Delete most build outputs (saves external repos).
    config    -- Create build output directory and run cmake config.
    all       -- Build binaries, libraries, unit tests, etc.
    rebuild   -- Alias for 'scrub config all'.
    test      -- Run unit tests.
    help      -- Print this message.

Configuration Variables:

  These configuration variables can be set on the command line or customized
  via included makefiles. To use the latter mechanism, set the environment
  variable HSE_MAKE_PRE_INCLUDE to refer to a GNU Make syntax file that will
  be inlined by this makefile. You can also define the environment variable
  HSE_MAKE_POST_INCLUDE to refer to a GNU Make syntax file that will be
  inlined at the bottom of this makefile. That mechanism can be used to add
  new targets that may be useful in a particular development workflow (see
  "Customization" below).

    BUILD_DIR     -- The build output directory.  Default value is BTOPDIR/BDIR.
                     BUILD_DIR can be set directly, in which case BTOPDIR and BDIR
                     are ignored, or BUILD_DIR can be set indirectly via BTOPDIR
                     and BDIR.  A common use case is to set BTOPDIR in
                     HSE_MAKE_PRE_INCLUDE and BDIR on the command line.
    BTOPDIR       -- See BUILD_DIR.
    BDIR          -- See BUILD_DIR.
    UBSAN         -- Enable the gcc undefined behavior sanitizer
    ASAN          -- Enable the gcc address/leak sanitizer
    DEPGRAPH      -- Set to "--graphviz=<filename_prefix>" to generate
                     graphviz dependency graph files
    REL_CANDIDATE -- When set builds a release candidate.

  Defaults:
    BUILD_DIR      = $$(BTOPDIR)/$$(BDIR)
    BTOPDIR        = $(BTOPDIR_DEFAULT)
    BDIR           = $(BDIR_DEFAULT)
    UBSAN          = $(UBSAN_DEFAULT)
    ASAN           = $(ASAN_DEFAULT)
    REL_CANDIDATE  = $(REL_CANDIDATE_DEFAULT)

Debug and Release Convenience Targets:

  Convenience targets are aimed at reducing the incidence of carpal tunnel
  syndrome among our highly valued development staff.  Including 'release' (or
  'debug') on the command line changes build type (and sets BDIR) to produce a
  release (or debug) build.

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


# SRC_DIR is set to the top of the this source tree.
SRC_DIR := $(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))

S=$(SRC_DIR)/scripts

################################################################
#
# Config defaults.
#
################################################################

ifeq ($(findstring relwithdebug,$(MAKECMDGOALS)),relwithdebug)
  BDIR_DEFAULT  := relwithdebug
  CFILE_DEFAULT := $(S)/cmake/relwithdebug.cmake
else ifeq ($(findstring optdebug,$(MAKECMDGOALS)),optdebug)
  BDIR_DEFAULT  := optdebug
  CFILE_DEFAULT := $(S)/cmake/optdebug.cmake
else ifeq ($(findstring debug,$(MAKECMDGOALS)),debug)
  BDIR_DEFAULT  := debug
  CFILE_DEFAULT := $(S)/cmake/debug.cmake
else ifeq ($(findstring relassert,$(MAKECMDGOALS)),relassert)
  BDIR_DEFAULT  := relassert
  CFILE_DEFAULT := $(S)/cmake/relassert.cmake
else
  # Default build mode is release
  BDIR_DEFAULT  := release
  CFILE_DEFAULT := $(S)/cmake/release.cmake
endif

BTOPDIR_DEFAULT       := $(SRC_DIR)/builds
BUILD_DIR_DEFAULT     := $(BTOPDIR_DEFAULT)/$(BDIR_DEFAULT)
BUILD_NUMBER_DEFAULT  := 0
UBSAN                 := 0
ASAN                  := 0
REL_CANDIDATE_DEFAULT := false

# Experimental: modify at your own risk
MPOOL_INCLUDE_DIR_DEFAULT := /usr/include
MPOOL_LIB_DIR_DEFAULT     := /usr/lib64

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

##############################################################################
#
# Set config var from defaults unless set by user on the command line or in
# HSE_MAKE_PRE_INCLUDE
#
##############################################################################
BTOPDIR           ?= $(BTOPDIR_DEFAULT)
BDIR              ?= $(BDIR_DEFAULT)
BUILD_DIR         ?= $(BTOPDIR)/$(BDIR)
CFILE             ?= $(CFILE_DEFAULT)
UBSAN             ?= $(UBSAN_DEFAULT)
ASAN              ?= $(ASAN_DEFAULT)
BUILD_NUMBER      ?= $(BUILD_NUMBER_DEFAULT)
REL_CANDIDATE     ?= $(REL_CANDIDATE_DEFAULT)

# Experimental: modify at your own risk
MPOOL_INCLUDE_DIR ?= $(MPOOL_INCLUDE_DIR_DEFAULT)
MPOOL_LIB_DIR     ?= $(MPOOL_LIB_DIR_DEFAULT)

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

RUN_CTEST = export HSE_BUILD_DIR="$(BUILD_DIR)"; set -e -u; cd "$(BUILD_DIR)"; ctest --output-on-failure $(CTEST_FLAGS)

RUN_CTEST_U = $(RUN_CTEST) $(CTEST_ULABEL)


define config-gen =
	(echo '# Note: When a variable is set multiple times in' ;\
	echo '#       this file, it is the *first* setting that' ;\
	echo '#       sticks!' ;\
	echo ;\
	echo 'set( MPOOL_INCLUDE_DIR "$(MPOOL_INCLUDE_DIR)" CACHE STRING "" FORCE)' ;\
	echo 'set( MPOOL_LIB_DIR "$(MPOOL_LIB_DIR)" CACHE STRING "" FORCE)' ;\
	echo 'set( UBSAN "$(UBSAN)" CACHE BOOL "" )' ;\
	echo 'set( ASAN "$(ASAN)" CACHE BOOL "" )' ;\
	echo 'set( BUILD_NUMBER "$(BUILD_NUMBER)" CACHE STRING "" )' ;\
	echo 'set( REL_CANDIDATE "$(REL_CANDIDATE)" CACHE STRING "" )' ;\
	if test "$(BUILD_SHA)"; then \
		echo 'set( HSE_SHA "$(BUILD_SHA)" CACHE STRING "")' ;\
	fi ;\
	echo ;\
	echo '# BEGIN: $(CFILE)' ;\
	cat  "$(CFILE)" ;\
	echo '# END:   $(CFILE)' ;\
	echo ;\
	echo '# BEGIN: $(S)/cmake/defaults.cmake' ;\
	cat  "$(S)/cmake/defaults.cmake" ;\
	echo '# END:   $(S)/cmake/defaults.cmake')
endef

# Delete the cmake config file if it has changed.
#
CONFIG = $(BUILD_DIR)/config.cmake

$(shell $(config-gen) | cmp -s - ${CONFIG} || rm -f ${CONFIG})


# If MAKECMDGOALS contains no goals other than any combination of
# BTYPES then make the given goals depend on the default goal.
#
BTYPES := debug release relwithdebug relassert optdebug asan ubsan
BTYPES := $(filter ${BTYPES},${MAKECMDGOALS})

ifeq ($(filter-out ${BTYPES},${MAKECMDGOALS}),)
BTYPESDEP := ${.DEFAULT_GOAL}
endif

.PHONY: all allv allq allqv allvq ${BTYPES}
.PHONY: clean config
.PHONY: distclean help install maintainer-clean package rebuild
.PHONY: test testp testv showtests showutests


# Goals in mostly alphabetical order.
#
all: config
	@$(MAKE) --no-print-directory -C "$(BUILD_DIR)" $(MF)
allv: config
	$(MAKE) -C "$(BUILD_DIR)" VERBOSE=1 $(MF)
allq: config
	$(MAKE) -C "$(BUILD_DIR)" $(MF) 2>&1 | $(PERL_CMAKE_NOISE_FILTER)
allqv allvq: config
	$(MAKE) -C "$(BUILD_DIR)" VERBOSE=1 $(MF) 2>&1 | $(PERL_CMAKE_NOISE_FILTER)

ifneq (${BTYPES},)
${BTYPES}: ${BTYPESDEP}
	@true
endif

clean:
	for d in $(patsubst %,${BUILD_DIR}/%,src cli test samples) ; do \
		if test -f "$$d/Makefile"; then \
			$(MAKE) --no-print-directory -C "$$d" clean ;\
		fi ;\
	done
	rm -rf "$(BUILD_DIR)"/*.rpm ;\

${CONFIG}: MAKEFLAGS += --no-print-directory
${CONFIG}: Makefile CMakeLists.txt ${CFILE} ${S}/cmake/defaults.cmake
	mkdir -p $(BUILD_DIR)
	rm -f $(BUILD_DIR)/CMakeCache.txt
	@$(config-gen) > $@.tmp
	cmake $(DEPGRAPH) $(CMAKE_FLAGS) -B $(BUILD_DIR) -C $@.tmp -S $(SRC_DIR)
	$(MAKE) -C $(BUILD_DIR) clean
	mv $@.tmp $@

config: $(SUBREPO_PATH_LIST) $(CONFIG)

distclean scrub:
	@if test -f ${CONFIG} ; then \
		rm -rf "$(BUILD_DIR)" ;\
	fi

help:
	@true
	$(info $(HELP_TEXT))

install: config
	@$(MAKE) --no-print-directory install -C "$(BUILD_DIR)"

maintainer-clean: distclean
ifneq ($(wildcard ${SUBREPO_PATH_LIST}),)
	rm -rf ${SUBREPO_PATH_LIST}
endif

package: config
	-rm "$(BUILD_DIR)"/hse*.rpm
	@$(MAKE) --no-print-directory -C "$(BUILD_DIR)" package

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
# settings of BUILD_DIR, BTOPDIR, and or BDIR in HSE_MAKE_PRE_INCLUDE).
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
