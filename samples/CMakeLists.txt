include_directories( ${HSE_INCLUDE_DIRS} )
include_directories( ${HSE_UTIL_INCLUDE_DIRS} )
include_directories( ${HSE_UT_BASE_INCLUDE_DIRS} )
include_directories( ${HSE_KVDB_UT_GS_INCLUDE_DIRS} )
include_directories( ${MPOOL_UT_GS_INCLUDE_DIRS} )

set( NON_TEST_LINK_LIBS
    hse_kvdb-lib
    mpool
    )

hse_executable(
    NAME ex1_create
    SRCS ex1_create.c
    LINK_DIRS
        ${MPOOL_LIB_DIR}
        ${BLKID_LIB_DIR}
    LINK_LIBS
        ${NON_TEST_LINK_LIBS}
        ${HSE_TEST_SUPPORT_LIBS}
    COMPONENT devel
    DESTINATION /opt/hse/bin
    )

hse_executable(
    NAME ex2_simple_ops
    SRCS ex2_simple_ops.c
    LINK_DIRS
        ${MPOOL_LIB_DIR}
        ${BLKID_LIB_DIR}
    LINK_LIBS
        ${NON_TEST_LINK_LIBS}
        ${HSE_TEST_SUPPORT_LIBS}
    COMPONENT devel
    DESTINATION /opt/hse/bin
    )

hse_executable(
    NAME ex3_cursor
    SRCS ex3_cursor.c
    LINK_DIRS
        ${MPOOL_LIB_DIR}
        ${BLKID_LIB_DIR}
    LINK_LIBS
        ${NON_TEST_LINK_LIBS}
        ${HSE_TEST_SUPPORT_LIBS}
    COMPONENT devel
    DESTINATION /opt/hse/bin
    )

hse_executable(
    NAME ex4_transactions
    SRCS ex4_transactions.c
    LINK_DIRS
        ${MPOOL_LIB_DIR}
        ${BLKID_LIB_DIR}
    LINK_LIBS
        ${NON_TEST_LINK_LIBS}
        ${HSE_TEST_SUPPORT_LIBS}
    COMPONENT devel
    DESTINATION /opt/hse/bin
    )

hse_executable(
    NAME ex5_large_val
    SRCS ex5_large_val.c
    LINK_DIRS
        ${MPOOL_LIB_DIR}
        ${BLKID_LIB_DIR}
    LINK_LIBS
        ${NON_TEST_LINK_LIBS}
        ${HSE_TEST_SUPPORT_LIBS}
    COMPONENT devel
    DESTINATION /opt/hse/bin
    )

hse_doc(
    NAME kvdb_examples
    SRCS 
        ex1_create.c
        ex2_simple_ops.c
        ex3_cursor.c
        ex4_transactions.c
        ex5_large_val.c
        Makefile
    DESTINATION ${HSE_DOCS_DIR}/examples
    COMPONENT devel
    )
