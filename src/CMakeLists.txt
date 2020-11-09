##############################################################################
#
# HSE KVDB Library
#
##############################################################################

set(HSE_TEST_LABELS kvdb)

message(STATUS "Configuring hse_kvdb in ${CMAKE_CURRENT_SOURCE_DIR}")

set( HSE_KVDB_PRIVATE_INCLUDE_DIRS
    ${PROJECT_SOURCE_DIR}/src/include
    )

set( HSE_COMPLETE_INCLUDE_DIRS
    ${HSE_INCLUDE_DIRS}
    ${HSE_KVDB_PRIVATE_INCLUDE_DIRS}
    ${HSE_UTIL_INCLUDE_DIRS}
    ${HSE_3RD_PARTY_INCLUDE_DIRS}
    ${MPOOL_INCLUDE_DIR}
    )

set( CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DCOMPNAME=\\\"kvdb\\\"" )

set( UTIL_SOURCE_FILES
    util/src/alloc.c
    util/src/bin_heap.c
    util/src/bloom_filter.c
    util/src/bonsai_tree.c
    util/src/bonsai_tree_balance.c
    util/src/bonsai_tree_pvt.h
    util/src/bonsai_tree_utils.c
    util/src/compression_lz4.c
    util/src/condvar.c
    util/src/config.c
    util/src/cursor_heap.c
    util/src/darray.c
    util/src/data_tree.c
    util/src/event_counter.c
    util/src/event_timer.c
    util/src/fmt.c
    util/src/hlog.c
    util/src/json.c
    util/src/key_util.c
    util/src/keylock.c
    util/src/logging.c
    util/src/logging_impl.h
    util/src/logging_util.c
    util/src/logging_util.h
    util/src/hse_err.c
    util/src/hse_log_fmt.c
    util/src/mtx_pool.c
    util/src/param.c
    util/src/parse_num.c
    util/src/parser.c
    util/src/parser_internal.h
    util/src/perfc.c
    util/src/pipe_find.c
    util/src/platform.c
    util/src/printbuf.c
    util/src/program_name.c
    util/src/rcu.c
    util/src/rest_api.c
    util/src/rest_client.c
    util/src/rest_dt.c
    util/src/rest_dt.h
    util/src/rmlock.c
    util/src/slab.c
    util/src/table.c
    util/src/time.c
    util/src/timer.c
    util/src/token_bucket.c
    util/src/version.c
    util/src/vlb.c
    util/src/workqueue.c
    util/src/xrand.c
    util/src/yaml.c
    ../3rdparty/src/cJSON.c
    ../3rdparty/src/lz4.c
    ../3rdparty/src/rbtree.c
    ../3rdparty/src/xxhash.c
    )

set( CN_SOURCE_FILES
     cn/blk_list.c
     cn/bloom_reader.c
     cn/cndb.c
     cn/cndb_omf.c
     cn/cn.c
     cn/cn_kvdb.c
     cn/cn_perfc.c
     cn/cn_tree.c
     cn/csched.c
     cn/csched_noop.c
     cn/csched_sp3.c
     cn/csched_sp3_work.c
     cn/kblock_builder.c
     cn/kblock_reader.c
     cn/keep.c
     cn/kvset.c
     cn/kvset_checker.c
     cn/kvset_builder.c
     cn/kcompact.c
     cn/mbset.c
     cn/hse_log_fmt.c
     cn/spill.c
     cn/vblock_builder.c
     cn/vblock_reader.c
     cn/wbt_builder.c
     cn/intern_builder.c
     cn/wbt_reader_v4.c
     cn/wbt_reader_v5.c
     cn/wbt_reader.c
     cn/vcomp_params.c
     )

set( C0_SOURCE_FILES
    c0/c0.c
    c0/c0_kvmultiset.c
    c0/c0_kvmsm.c
    c0/c0_kvset.c
    c0/c0_kvsetm.c
    c0/c0_kvset_iterator.c
    c0/c0_ingest_work.c
    c0/c0sk.c
    c0/c0skm.c
    c0/c0sk_internal.c
    c0/c0sk_perfc.c
    c0/kvb_builder.c
     )

set( KVDB_SOURCE_FILES
    kvdb/kvdb_log.c
    kvdb/ikvdb.c
    kvdb/kvdb_ctxn.c
    kvdb/ctxn_perfc.c
    kvdb/kvdb_keylock.c
    kvdb/active_ctxn_set.c
    kvdb/kvdb_health.c
    kvdb/kvdb_cparams.c
    kvdb/kvdb_rparams.c
    kvdb/hse_params.c
    kvdb/throttle.c
    kvdb/wp.c
    kvdb/kvdb_rest.c
    kvdb/sched_sts.c
    kvdb/sched_sts_perfc.c
    kvdb/mclass_policy.c
     )

set( KVS_SOURCE_FILES
    kvs/kvs_rparams.c
    kvs/kvs_cparams.c
    kvs/kvs.c
    kvs/query_ctx.c
    )

set( C1_SOURCE_FILES
    c1/c1_journal.c
    c1/c1_journal_utils.c
    c1/c1_tree.c
    c1/c1_tree_utils.c
    c1/c1_log.c
    c1/c1_log_utils.c
    c1/c1_ops.c
    c1/c1_utils.c
    c1/c1_io.c
    c1/c1_compact.c
    c1/c1_kv.c
    c1/c1_perfc.c
    c1/c1_diag.c
    c1/c1_omf.c
    )

set( BINDING_SOURCE_FILES
    binding/kvdb_interface.c
    binding/kvdb_experimental_interface.c
    binding/kvdb_perfc.c
    binding/diag_kvdb_interface.c
    )

set( KVDB_LIB_SOURCE_FILES
    ${BINDING_SOURCE_FILES}
    ${C0_SOURCE_FILES}
    ${CN_SOURCE_FILES}
    ${KVS_SOURCE_FILES}
    ${KVDB_SOURCE_FILES}
    ${C1_SOURCE_FILES}
    ${UTIL_SOURCE_FILES}
    )


if( HSE_UNIT_TEST_FLAG )

    # sets MPOOL_UT_GS_INCLUDE_DIRS
    hse_ut_publish_include_dirs(COMPONENT mpool)

    # sets HSE_KVDB_INCLUDE_UT_GS_INCLUDE_DIRS
    hse_ut_publish_include_dirs(COMPONENT hse_kvdb_include)

    # sets HSE_BINDING_UT_GS_INCLUDE_DIRS
    hse_ut_publish_include_dirs(COMPONENT hse_binding )

    # sets HSE_KVDB_UT_GS_INCLUDE_DIRS
    hse_ut_publish_include_dirs(COMPONENT hse_kvdb)

    # sets HSE_IKVDB_UT_GS_INCLUDE_DIRS
    hse_ut_publish_include_dirs(COMPONENT hse_ikvdb)

    # sets HSE_C0_UT_GS_INCLUDE_DIRS
    hse_ut_publish_include_dirs(COMPONENT hse_c0)

    # sets HSE_C1_UT_GS_INCLUDE_DIRS
    hse_ut_publish_include_dirs(COMPONENT hse_c1)

    # sets HSE_CN_UT_GS_INCLUDE_DIRS
    hse_ut_publish_include_dirs(COMPONENT hse_cn)

    # sets HSE_UTIL_UT_GS_INCLUDE_DIRS
    hse_ut_publish_include_dirs(COMPONENT hse_util)

endif()

#
# Definition of hse_kvdb-lib and hse_kvdb_static-lib
#

set( HSE_KVDB_LIB_DEPS
    libyaml-ext
    libcurl-ext
    )

set( HSE_KVDB_LIB_LINK_LIBS
    ${LIBCURL_LIBS}
    ${LIBYAML_LIBS}
    urcu-bp
    uuid
    pthread
    microhttpd
    mpool
    mpool-blkid
    m
    )

set( HSE_KVDB_LIB_INCLUDES
    ${HSE_COMPLETE_INCLUDE_DIRS}
    ${HSE_TEST_INCLUDE_DIRS}
    ${HSE_TEST_LIB_INCLUDE_DIRS}
    ${HSE_UTIL_PRIVATE_UT_GS_INCLUDE_DIRS}
    ${HSE_TEST_SUPPORT_UT_GS_INCLUDE_DIRS}
    ${HSE_UT_FMWK_INCLUDE_DIRS}
    ${HSE_UTIL_UT_GS_INCLUDE_DIRS}
    ${HSE_C0_UT_GS_INCLUDE_DIRS}
    ${HSE_C1_UT_GS_INCLUDE_DIRS}
    ${HSE_CN_UT_GS_INCLUDE_DIRS}
    ${HSE_KVDB_UT_GS_INCLUDE_DIRS}
    ${HSE_KVDB_INCLUDE_UT_GS_INCLUDE_DIRS}
    ${HSE_IKVDB_UT_GS_INCLUDE_DIRS}
    ${MPOOL_UT_GS_INCLUDE_DIRS}
    )

hse_library(
    NAME hse_kvdb
    OUTPUT_NAME hse_kvdb
    COMPONENT runtime
    MODE SHARED
    SRCS ${KVDB_LIB_SOURCE_FILES}
    DEPS ${HSE_KVDB_LIB_DEPS}
    LINK_DIRS
        ${MPOOL_LIB_DIR}
        ${BLKID_LIB_DIR}
    LINK_LIBS ${HSE_KVDB_LIB_LINK_LIBS}
    INCLUDES ${HSE_KVDB_LIB_INCLUDES}
    )

hse_library(
    NAME hse_kvdb_static
    OUTPUT_NAME hse_kvdb_static
    MODE STATIC
    # COMPONENT runtime <-- uncomment to install
    SRCS ${KVDB_LIB_SOURCE_FILES}
    DEPS ${HSE_KVDB_LIB_DEPS}
    LINK_DIRS
        ${MPOOL_LIB_DIR}
        ${BLKID_LIB_DIR}
    LINK_LIBS ${HSE_KVDB_LIB_LINK_LIBS}
    INCLUDES ${HSE_KVDB_LIB_INCLUDES}
    )

if( HSE_UNIT_TEST_FLAG )
    target_link_libraries( hse_kvdb-lib ${HSE_TEST_SUPPORT_LIBS} )
endif()

if( HSE_UNIT_TEST_FLAG )
    target_link_libraries( hse_kvdb_static-lib ${HSE_TEST_SUPPORT_LIBS} )
endif()

set (HSE_USER_MPOOL_LINK_LIBS
     pthread
     mpool
     ${HSE_TEST_SUPPORT_LIBS}
)

hse_executable(
    NAME mpool_profile
    SRCS tools/mpool_profile.c
    INCLUDES ${HSE_COMPLETE_INCLUDE_DIRS}
    LINK_DIRS
        ${MPOOL_LIB_DIR}
        ${BLKID_LIB_DIR}
    LINK_LIBS
        hse_kvdb_static-lib
        ${HSE_USER_MPOOL_LINK_LIBS}
        m
    DESTINATION ${HSE_DIAG_BIN}
    COMPONENT runtime
)

hse_executable(
    NAME cn_metrics
    SRCS tools/cn_metrics.c
    INCLUDES ${HSE_COMPLETE_INCLUDE_DIRS}
    LINK_DIRS
        ${MPOOL_LIB_DIR}
        ${BLKID_LIB_DIR}
    LINK_LIBS
        hse_kvdb_static-lib
        ${HSE_USER_MPOOL_LINK_LIBS}
    DESTINATION ${HSE_DIAG_BIN}
    COMPONENT runtime
)

hse_executable(
    NAME cn_kbdump
    SRCS tools/cn_kbdump.c
    INCLUDES ${HSE_COMPLETE_INCLUDE_DIRS}
    LINK_DIRS
        ${MPOOL_LIB_DIR}
        ${BLKID_LIB_DIR}
    LINK_LIBS
        hse_kvdb_static-lib
        ${HSE_USER_MPOOL_LINK_LIBS}
    DESTINATION ${HSE_DIAG_BIN}
    COMPONENT runtime
)

hse_executable(
    NAME kvck
    SRCS tools/kvck.c
    INCLUDES ${HSE_COMPLETE_INCLUDE_DIRS}
    LINK_DIRS
        ${MPOOL_LIB_DIR}
        ${BLKID_LIB_DIR}
    LINK_LIBS
        hse_kvdb_static-lib
        ${HSE_USER_MPOOL_LINK_LIBS}
    DESTINATION ${HSE_DIAG_BIN}
    COMPONENT runtime
)

hse_executable(
    NAME cndb_log
    SRCS tools/cndb_log.c
    INCLUDES ${HSE_COMPLETE_INCLUDE_DIRS}
    LINK_DIRS
        ${MPOOL_LIB_DIR}
        ${BLKID_LIB_DIR}
    LINK_LIBS
        hse_kvdb_static-lib
        ${HSE_USER_MPOOL_LINK_LIBS}
    DESTINATION ${HSE_DIAG_BIN}
    COMPONENT runtime
)

hse_executable(
    NAME c1log
    SRCS tools/c1log.c
    INCLUDES ${HSE_COMPLETE_INCLUDE_DIRS}
    LINK_DIRS
        ${MPOOL_LIB_DIR}
        ${BLKID_LIB_DIR}
    LINK_LIBS
        hse_kvdb_static-lib
        ${HSE_USER_MPOOL_LINK_LIBS}
    DESTINATION ${HSE_DIAG_BIN}
    COMPONENT runtime
)

hse_executable(
    NAME mdc_tool
    SRCS tools/mdc_tool.c
    INCLUDES ${HSE_COMPLETE_INCLUDE_DIRS}
    LINK_DIRS
        ${MPOOL_LIB_DIR}
        ${BLKID_LIB_DIR}
    LINK_LIBS
        hse_kvdb_static-lib
        ${HSE_USER_MPOOL_LINK_LIBS}
    DESTINATION ${HSE_DIAG_BIN}
    COMPONENT runtime
)

hse_executable(
    NAME cndb_raw_inject
    SRCS cn/test/cndb_raw_inject.c
    INCLUDES ${HSE_COMPLETE_INCLUDE_DIRS}
    LINK_DIRS
        ${MPOOL_LIB_DIR}
        ${BLKID_LIB_DIR}
    LINK_LIBS
        hse_kvdb_static-lib
        ${HSE_USER_MPOOL_LINK_LIBS}
    DESTINATION ${HSE_DIAG_BIN}
    COMPONENT runtime
)

hse_executable(
    NAME cndb_txn_inject
    SRCS cn/test/cndb_txn_inject.c
    INCLUDES ${HSE_COMPLETE_INCLUDE_DIRS}
    LINK_DIRS
        ${MPOOL_LIB_DIR}
        ${BLKID_LIB_DIR}
    LINK_LIBS
        hse_kvdb_static-lib
        ${HSE_USER_MPOOL_LINK_LIBS}
    DESTINATION ${HSE_DIAG_BIN}
    COMPONENT runtime
)

hse_executable(
    NAME cndb_simpledrop_inject
    SRCS cn/test/cndb_simpledrop_inject.c
    INCLUDES ${HSE_COMPLETE_INCLUDE_DIRS}
    LINK_DIRS
        ${MPOOL_LIB_DIR}
        ${BLKID_LIB_DIR}
    LINK_LIBS
        hse_kvdb_static-lib
        ${HSE_USER_MPOOL_LINK_LIBS}
    DESTINATION ${HSE_DIAG_BIN}
    COMPONENT runtime
)

hse_executable(
    NAME cndb_simpledrop_recovery_inject
    SRCS cn/test/cndb_simpledrop_recovery_inject.c
    INCLUDES ${HSE_COMPLETE_INCLUDE_DIRS}
    LINK_DIRS
        ${MPOOL_LIB_DIR}
        ${BLKID_LIB_DIR}
    LINK_LIBS
        hse_kvdb_static-lib
        ${HSE_USER_MPOOL_LINK_LIBS}
    DESTINATION ${HSE_DIAG_BIN}
    COMPONENT runtime
)

##############################################################################
#
# Unit Test Infrastructure
#
##############################################################################

if( HSE_UNIT_TEST_FLAG )

    set( UT_INCLUDE_DIRS
        ${HSE_COMPLETE_INCLUDE_DIRS}
        ${HSE_UT_BASE_INCLUDE_DIRS}
        ${HSE_3RD_PARTY_INCLUDE_DIRS}
        ${HSE_TEST_SUPPORT_UT_GS_INCLUDE_DIRS}
        ${HSE_UTIL_UT_GS_INCLUDE_DIRS}
        )

    # hse_kvdb_static-lib depends on mocking mpool interfaces
    hse_ut_mock_generate(
        DEPENDENTS hse_kvdb_static-lib
        GENSRC_PREFIX mpool
        SEARCH_DIRS ${MPOOL_INCLUDE_DIR}/mpool
        )
    set( UT_INCLUDE_DIRS ${UT_INCLUDE_DIRS}
        ${MPOOL_UT_GS_INCLUDE_DIRS}
        )

    # hse_kvdb_static-lib depends on mocking include/hse_kvdb interfaces
    hse_ut_mock_generate(
        DEPENDENTS hse_kvdb_static-lib
        GENSRC_PREFIX hse_kvdb_include
        SEARCH_DIRS ${PROJECT_SOURCE_DIR}/include/hse
        )
    set( UT_INCLUDE_DIRS ${UT_INCLUDE_DIRS}
        ${HSE_KVDB_INCLUDE_UT_GS_INCLUDE_DIRS}
        )

    # hse_kvdb_static-lib depends on mocking src/binding interfaces
    hse_ut_mock_generate(
        DEPENDENTS hse_kvdb_static-lib
        GENSRC_PREFIX hse_binding
        SEARCH_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/binding
        )
    set( UT_INCLUDE_DIRS ${UT_INCLUDE_DIRS}
        ${HSE_BINDING_UT_GS_INCLUDE_DIRS}
        )

    # hse_kvdb_static-lib depends on mocking src/kvdb interfaces
    hse_ut_mock_generate(
        DEPENDENTS hse_kvdb_static-lib
        GENSRC_PREFIX hse_kvdb
        SEARCH_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/kvdb
        )
    set( UT_INCLUDE_DIRS ${UT_INCLUDE_DIRS}
        ${HSE_KVDB_UT_GS_INCLUDE_DIRS}
        )

    # hse_kvdb_static-lib depends on mocking src/include/hse_ikvdb interfaces
    hse_ut_mock_generate(
        DEPENDENTS hse_kvdb_static-lib
        GENSRC_PREFIX hse_ikvdb
        SEARCH_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/include/hse_ikvdb
        )
    set( UT_INCLUDE_DIRS ${UT_INCLUDE_DIRS}
        ${HSE_IKVDB_UT_GS_INCLUDE_DIRS}
        )

    # hse_kvdb_static-lib depends on mocking src/c0 interfaces
    hse_ut_mock_generate(
        DEPENDENTS hse_kvdb_static-lib
        GENSRC_PREFIX hse_c0
        SEARCH_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/c0
        )
    set( UT_INCLUDE_DIRS ${UT_INCLUDE_DIRS}
        ${HSE_C0_UT_GS_INCLUDE_DIRS}
        )

    # hse_kvdb_static-lib depends on mocking src/c0 interfaces
    hse_ut_mock_generate(
        DEPENDENTS hse_kvdb_static-lib
        GENSRC_PREFIX hse_c1
        SEARCH_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/c1
        )
    set( UT_INCLUDE_DIRS ${UT_INCLUDE_DIRS}
        ${HSE_C1_UT_GS_INCLUDE_DIRS}
        )

    # hse_kvdb_static-lib depends on mocking src/cn interfaces
    hse_ut_mock_generate(
        DEPENDENTS hse_kvdb_static-lib
        GENSRC_PREFIX hse_cn
        SEARCH_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/cn
        )
    set( UT_INCLUDE_DIRS ${UT_INCLUDE_DIRS}
        ${HSE_CN_UT_GS_INCLUDE_DIRS}
        )

    # hse_kvdb_static-lib depends on mocking src/util interfaces
    hse_ut_mock_generate(
        DEPENDENTS
        hse_kvdb_static-lib
        hse_test_support-lib
        GENSRC_PREFIX hse_util
        SEARCH_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/util
        )
    set( UT_INCLUDE_DIRS ${UT_INCLUDE_DIRS}
        ${HSE_UTIL_UT_GS_INCLUDE_DIRS}
        )

    hse_library(
        NAME hse_mock
        MODE STATIC
        DEPS ${UNIT_TEST_LINK_LIBS}
        CFLAGS -DHSE_UNIT_TEST_MODE=1
        SRCS
            cn/test/mock_mpool.c
            cn/test/mock_kbb_vbb.c
            cn/test/mock_kvset.c
            cn/test/mock_kvset_builder.c
            kvdb/test/mock_c0cn.c
            kvdb/test/mock_c1.c
        INCLUDES
            ${HSE_UTIL_INCLUDE_DIRS}
            ${HSE_TEST_INCLUDE_DIRS}
            ${HSE_TEST_LIB_INCLUDE_DIRS}
            ${HSE_UT_FMWK_INCLUDE_DIRS}
            ${HSE_COMPLETE_INCLUDE_DIRS}
            ${HSE_UT_BASE_INCLUDE_DIRS}
            ${HSE_TEST_SUPPORT_UT_GS_INCLUDE_DIRS}
            ${HSE_UTIL_UT_GS_INCLUDE_DIRS}
            ${HSE_C0_UT_GS_INCLUDE_DIRS}
            ${HSE_C1_UT_GS_INCLUDE_DIRS}
            ${HSE_CN_UT_GS_INCLUDE_DIRS}
            ${HSE_KVDB_UT_GS_INCLUDE_DIRS}
            ${HSE_KVDB_INCLUDE_UT_GS_INCLUDE_DIRS}
            ${HSE_IKVDB_UT_GS_INCLUDE_DIRS}
            ${MPOOL_UT_GS_INCLUDE_DIRS}
        )

    set( UNIT_TEST_INCLUDE_DIRS
        ${UT_INCLUDE_DIRS}
        ${HSE_TEST_INCLUDE_DIRS} 
        ${HSE_UT_FMWK_INCLUDE_DIRS}
        )

    set( UNIT_TEST_LINK_LIBS
        hse_kvdb_static-lib
        hse_mock-lib
        mpool
        ${HSE_TEST_SUPPORT_LIBS}
        )

    hse_unit_test(
        NAME cndb_test
        INCLUDES ${UNIT_TEST_INCLUDE_DIRS}
        LABELS cn
        SRCS cn/test/cndb_test.c
        LINK_LIBS ${UNIT_TEST_LINK_LIBS}
        )

    hse_unit_test(
        NAME cndb_log_test
        COMMAND cndb_log_test ${CMAKE_CURRENT_SOURCE_DIR}/cn/test/mdc_images
        LABELS cn
        SRCS cn/test/cndb_log_test.c
        INCLUDES
            ${UNIT_TEST_INCLUDE_DIRS}
            ${HSE_COMPLETE_INCLUDE_DIRS}
        LINK_LIBS ${UNIT_TEST_LINK_LIBS}
        )

    hse_unit_test(
        NAME cn_api_test
        LABELS cn
        SRCS cn/test/cn_api_test.c
        INCLUDES ${UNIT_TEST_INCLUDE_DIRS}
        LINK_LIBS ${UNIT_TEST_LINK_LIBS}
        )

    hse_unit_test(
        NAME cn_cursor_test
        COMMAND cn_cursor_test
        LABELS cn
        SRCS cn/test/cn_cursor_test.c
        INCLUDES ${UNIT_TEST_INCLUDE_DIRS}
        LINK_LIBS ${UNIT_TEST_LINK_LIBS}
        )

    hse_unit_test(
        NAME cn_ingest_test
        LABELS cn
        SRCS cn/test/cn_ingest_test.c
        INCLUDES ${UNIT_TEST_INCLUDE_DIRS}
        LINK_LIBS ${UNIT_TEST_LINK_LIBS}
        )

    hse_unit_test(
        NAME blk_list_test
        LABELS cn
        SRCS cn/test/blk_list_test.c
        INCLUDES ${UNIT_TEST_INCLUDE_DIRS}
        LINK_LIBS ${UNIT_TEST_LINK_LIBS}
        )

    hse_unit_test(
        NAME bloom_reader_test
        COMMAND bloom_reader_test ${CMAKE_CURRENT_SOURCE_DIR}/cn/test/mblock_images
        LABELS cn
        SRCS cn/test/bloom_reader_test.c
        INCLUDES ${UNIT_TEST_INCLUDE_DIRS}
        LINK_LIBS ${UNIT_TEST_LINK_LIBS}
        )

    hse_unit_test(
        NAME wbt_reader_test
        COMMAND wbt_reader_test ${CMAKE_CURRENT_SOURCE_DIR}/cn/test/mblock_images
        LABELS cn
        SRCS cn/test/wbt_reader_test.c
        INCLUDES ${UNIT_TEST_INCLUDE_DIRS}
        LINK_LIBS ${UNIT_TEST_LINK_LIBS}
        )

    hse_unit_test(
        NAME wbt_test
        LABELS cn
        SRCS cn/test/wbt_test.c
        INCLUDES ${UNIT_TEST_INCLUDE_DIRS}
        LINK_LIBS ${UNIT_TEST_LINK_LIBS}
        )

    hse_unit_test(
        NAME wbt_iterator_test
        COMMAND wbt_iterator_test ${CMAKE_CURRENT_SOURCE_DIR}/cn/test/mblock_images
        LABELS cn
        SRCS cn/test/wbt_iterator_test.c
        INCLUDES ${UNIT_TEST_INCLUDE_DIRS}
        LINK_LIBS ${UNIT_TEST_LINK_LIBS}
        )

    hse_unit_test(
        NAME kblock_reader_test
        LABELS cn
        SRCS cn/test/kblock_reader_test.c
        INCLUDES ${UNIT_TEST_INCLUDE_DIRS}
        LINK_LIBS ${UNIT_TEST_LINK_LIBS}
        )

    hse_unit_test(
        NAME vblock_reader_test
        INCLUDES ${UNIT_TEST_INCLUDE_DIRS}
        LABELS cn
        SRCS cn/test/vblock_reader_test.c
        LINK_LIBS ${UNIT_TEST_LINK_LIBS}
        )

    hse_unit_test(
        NAME kblock_builder_test
        LABELS cn
        SRCS cn/test/kblock_builder_test.c
        INCLUDES ${UNIT_TEST_INCLUDE_DIRS}
        LINK_LIBS ${UNIT_TEST_LINK_LIBS}
        )

    hse_unit_test(
        NAME vblock_builder_test
        LABELS cn
        SRCS cn/test/vblock_builder_test.c
        INCLUDES ${UNIT_TEST_INCLUDE_DIRS}
        LINK_LIBS ${UNIT_TEST_LINK_LIBS}
        )

    hse_unit_test(
        NAME kvset_builder_test
        LABELS cn
        SRCS cn/test/kvset_builder_test.c
        INCLUDES ${UNIT_TEST_INCLUDE_DIRS}
        LINK_LIBS ${UNIT_TEST_LINK_LIBS}
        )

    hse_unit_test(
        NAME mbset_test
        LABELS cn
        SRCS cn/test/mbset_test.c
        INCLUDES ${UNIT_TEST_INCLUDE_DIRS}
        LINK_LIBS ${UNIT_TEST_LINK_LIBS}
        )

    hse_unit_test(
        NAME cn_tree_test
        LABELS cn
        SRCS cn/test/cn_tree_test.c
        INCLUDES ${UNIT_TEST_INCLUDE_DIRS}
        LINK_LIBS ${UNIT_TEST_LINK_LIBS}
        )

    hse_unit_test(
        NAME cn_make_test
        LABELS cn
        SRCS cn/test/cn_make_test.c
        INCLUDES ${UNIT_TEST_INCLUDE_DIRS}
        LINK_LIBS ${UNIT_TEST_LINK_LIBS}
        )

    hse_unit_test(
        NAME cn_open_test
        LABELS cn
        SRCS cn/test/cn_open_test.c
        INCLUDES ${UNIT_TEST_INCLUDE_DIRS}
        LINK_LIBS ${UNIT_TEST_LINK_LIBS}
        )

    hse_unit_test(
        NAME cn_perfc_test
        LABELS cn
        SRCS cn/test/cn_perfc_test.c
        INCLUDES ${UNIT_TEST_INCLUDE_DIRS}
        LINK_LIBS ${UNIT_TEST_LINK_LIBS}
        )

    hse_unit_test(
        NAME cn_mblock_test
        LABELS cn
        SRCS cn/test/cn_mblock_test.c
        INCLUDES ${UNIT_TEST_INCLUDE_DIRS}
        LINK_LIBS ${UNIT_TEST_LINK_LIBS}
        )

    hse_unit_test(
        NAME c0_test
        LABELS c0
        SRCS
            c0/test/c0_test.c
            c0/test/cn_mock.c
            c0/test/c0sk_mock.c
            kvdb/test/mock_c1.c
        INCLUDES ${UNIT_TEST_INCLUDE_DIRS}
        LINK_LIBS ${UNIT_TEST_LINK_LIBS}
        )

    hse_unit_test(
        NAME c0sk_test
        LABELS c0sk
        SRCS
            c0/test/c0sk_test.c
            c0/test/cn_mock.c
        INCLUDES ${UNIT_TEST_INCLUDE_DIRS}
        LINK_LIBS ${UNIT_TEST_LINK_LIBS}
        )

    hse_unit_test(
        NAME c0_kvset_test
        LABELS c0
        SRCS c0/test/c0_kvset_test.c
        INCLUDES ${UNIT_TEST_INCLUDE_DIRS}
        LINK_LIBS ${UNIT_TEST_LINK_LIBS}
        )

    hse_unit_test(
        NAME c0_kvset_iterator_test
        LABELS c0
        SRCS c0/test/c0_kvset_iterator_test.c
        INCLUDES ${UNIT_TEST_INCLUDE_DIRS}
        LINK_LIBS ${UNIT_TEST_LINK_LIBS}
        )

    hse_unit_test(
        NAME c0_kvmultiset_test
        LABELS c0
        SRCS c0/test/c0_kvmultiset_test.c
        INCLUDES ${UNIT_TEST_INCLUDE_DIRS}
        LINK_LIBS ${UNIT_TEST_LINK_LIBS}
        )

    hse_unit_test(
        NAME c0skm_test
        LABELS c0
        SRCS c0/test/c0skm_test.c
        INCLUDES ${UNIT_TEST_INCLUDE_DIRS}
        LINK_LIBS ${UNIT_TEST_LINK_LIBS}
        )

    hse_unit_test(
        NAME merge_test
        LABELS cn
        COMMAND merge_test ${CMAKE_CURRENT_SOURCE_DIR}/cn/test/merge-test-cases
        SRCS cn/test/merge_test.c
        INCLUDES ${UNIT_TEST_INCLUDE_DIRS}
        LINK_LIBS ${UNIT_TEST_LINK_LIBS} ${LIBYAML_LIBS}
        )

    hse_unit_test(
        NAME kcompact_test
        LABELS cn
        SRCS cn/test/kcompact_test.c
        INCLUDES ${UNIT_TEST_INCLUDE_DIRS}
        LINK_LIBS ${UNIT_TEST_LINK_LIBS}
        )

    hse_unit_test(
        NAME kvs_rparams_test
        SRCS kvs/test/kvs_rparams_test.c
        INCLUDES ${UNIT_TEST_INCLUDE_DIRS}
        LINK_LIBS ${UNIT_TEST_LINK_LIBS}
        )

    hse_unit_test(
        NAME kvs_cparams_test
        SRCS kvs/test/kvs_cparams_test.c
        INCLUDES ${UNIT_TEST_INCLUDE_DIRS}
        LINK_LIBS ${UNIT_TEST_LINK_LIBS}
        )

    hse_unit_test(
        NAME kvdb_rparams_test
        SRCS kvdb/test/kvdb_rparams_test.c
        INCLUDES ${UNIT_TEST_INCLUDE_DIRS}
        LINK_LIBS ${UNIT_TEST_LINK_LIBS}
        )

    hse_unit_test(
        NAME kvdb_cparams_test
        SRCS kvdb/test/kvdb_cparams_test.c
        INCLUDES ${UNIT_TEST_INCLUDE_DIRS}
        LINK_LIBS ${UNIT_TEST_LINK_LIBS}
        )

    hse_unit_test(
        NAME kvdb_log_test
        COMMAND kvdb_log_test ${CMAKE_CURRENT_SOURCE_DIR}/cn/test/mdc_images
        SRCS kvdb/test/kvdb_log_test.c
        INCLUDES ${UNIT_TEST_INCLUDE_DIRS}
        LINK_LIBS ${UNIT_TEST_LINK_LIBS}
        )

#    # REVISIT: cn_logging_test test periodically fails because the
#    # because the syslog/vsyslog functions underlying hse_xlog() are
#    # intercepted to save log messages into a shared buffer. But
#    # there are multiple threads that use syslog/vsyslog, so by the
#    # time this message is parsed by process_json_payload(), the
#    # buffer could have been reused.
#
#    hse_unit_test(
#        NAME cn_logging_test
#        LABELS cn
#        SRCS cn/test/cn_logging_test.c
#        INCLUDES ${UNIT_TEST_INCLUDE_DIRS}
#        LINK_LIBS ${UNIT_TEST_LINK_LIBS}
#        )

    hse_unit_test(
        NAME kvdb_ctxn_test
        SRCS kvdb/test/kvdb_ctxn_test.c
        INCLUDES ${UNIT_TEST_INCLUDE_DIRS}
        LINK_LIBS ${UNIT_TEST_LINK_LIBS}
        )

    hse_unit_test(
        NAME ctxn_perfc_test
        SRCS kvdb/test/ctxn_perfc_test.c
        INCLUDES ${UNIT_TEST_INCLUDE_DIRS}
        LINK_LIBS ${UNIT_TEST_LINK_LIBS}
        )

    # Run sched_sts_test twice: once without debug rparam set,
    # and once with debug rparam set.  This results in higher
    # branch coverage.
    hse_unit_test(
        NAME sched_sts_test
        COMMAND sched_sts_test
        SRCS kvdb/test/sched_sts_test.c
        INCLUDES ${UNIT_TEST_INCLUDE_DIRS}
        LINK_LIBS ${UNIT_TEST_LINK_LIBS}
        )

    hse_unit_test(
        NAME sched_sts_test_debug
        COMMAND sched_sts_test_debug debug
        SRCS kvdb/test/sched_sts_test.c
        INCLUDES ${UNIT_TEST_INCLUDE_DIRS}
        LINK_LIBS ${UNIT_TEST_LINK_LIBS}
        )

    # Run csched_test twice: once without debug rparam set,
    # and once with debug rparam set.  This results in higher
    # branch coverage.
    hse_unit_test(
        NAME csched_test
        COMMAND csched_test
        SRCS cn/test/csched_test.c
        INCLUDES ${UNIT_TEST_INCLUDE_DIRS}
        LINK_LIBS ${UNIT_TEST_LINK_LIBS}
        )
    hse_unit_test(
        NAME csched_test_debug
        COMMAND csched_test_debug debug
        SRCS cn/test/csched_test.c
        INCLUDES ${UNIT_TEST_INCLUDE_DIRS}
        LINK_LIBS ${UNIT_TEST_LINK_LIBS}
        )

    hse_unit_test(
        NAME csched_sp3_test
        SRCS cn/test/csched_sp3_test.c
        INCLUDES ${UNIT_TEST_INCLUDE_DIRS}
        LINK_LIBS ${UNIT_TEST_LINK_LIBS}
        )

    hse_unit_test(
        NAME csched_noop_test
        SRCS cn/test/csched_noop_test.c
        INCLUDES ${UNIT_TEST_INCLUDE_DIRS}
        LINK_LIBS ${UNIT_TEST_LINK_LIBS}
        )

    hse_unit_test(
        NAME kvdb_keylock_test
        SRCS kvdb/test/kvdb_keylock_test.c
        INCLUDES ${UNIT_TEST_INCLUDE_DIRS}
        LINK_LIBS ${UNIT_TEST_LINK_LIBS}
        )

    hse_unit_test(
        NAME ikvdb_test
        SRCS kvdb/test/ikvdb_test.c
        INCLUDES ${UNIT_TEST_INCLUDE_DIRS}
        LINK_DIRS
            ${MPOOL_LIB_DIR}
            ${BLKID_LIB_DIR}
        LINK_LIBS ${UNIT_TEST_LINK_LIBS}
        )

    hse_unit_test(
        NAME kvdb_rest_test
        SRCS kvdb/test/kvdb_rest_test.c
        INCLUDES ${UNIT_TEST_INCLUDE_DIRS}
        DEPS libcurl-ext
        LINK_DIRS
            ${MPOOL_LIB_DIR}
            ${BLKID_LIB_DIR}
        LINK_LIBS ${UNIT_TEST_LINK_LIBS} ${LIBCURL_LIBS}
        )

    hse_unit_test(
        NAME kvdb_test
        INCLUDES ${UNIT_TEST_INCLUDE_DIRS}
        SRCS kvdb/test/kvdb_test.c util/test/mock_log.c
        LINK_LIBS ${UNIT_TEST_LINK_LIBS}
        )

    hse_unit_test(
        NAME hse_params_test
        SRCS kvdb/test/hse_params_test.c
        INCLUDES ${UNIT_TEST_INCLUDE_DIRS}
        LINK_LIBS ${UNIT_TEST_LINK_LIBS}
        )

    hse_unit_test(
        NAME throttle_test
        SRCS kvdb/test/throttle_test.c
        INCLUDES ${UNIT_TEST_INCLUDE_DIRS}
        LINK_LIBS ${UNIT_TEST_LINK_LIBS}
        )

    hse_unit_test(
        NAME wp_test
        COMMAND wp_test ${PROJECT_SOURCE_DIR}/config
        SRCS kvdb/test/wp_test.c
        INCLUDES ${UNIT_TEST_INCLUDE_DIRS}
        LINK_LIBS ${UNIT_TEST_LINK_LIBS}
        )

    hse_unit_test(
        NAME encoder_perf
        LABELS cn
        SRCS cn/test/encoder_perf.c
        INCLUDES ${UNIT_TEST_INCLUDE_DIRS}
        LINK_LIBS ${UNIT_TEST_LINK_LIBS}
        )

    hse_unit_test(
        NAME c1_test
        LABELS c1
        SRCS
            c0/test/cn_mock.c
            c1/test/c1_test.c
            c1/test/mock_mpool.c
        INCLUDES ${UNIT_TEST_INCLUDE_DIRS}
        LINK_LIBS ${UNIT_TEST_LINK_LIBS}
        )

    hse_unit_test(
        NAME c1_make_test
        LABELS c1
        SRCS
            c1/test/c1_make_test.c
            c1/test/mock_mpool.c
        INCLUDES ${UNIT_TEST_INCLUDE_DIRS}
        LINK_LIBS ${UNIT_TEST_LINK_LIBS}
        )

    hse_unit_test(
        NAME c1_txn_test
        LABELS c1
        SRCS
            c0/test/cn_mock.c
            c1/test/c1_txn_test.c
            c1/test/mock_mpool.c
        INCLUDES ${UNIT_TEST_INCLUDE_DIRS}
        LINK_LIBS ${UNIT_TEST_LINK_LIBS}
        )

    hse_unit_test(
        NAME c1_slist_test
        LABELS c1
        SRCS c1/test/c1_slist_test.c
        INCLUDES ${UNIT_TEST_INCLUDE_DIRS}
        LINK_LIBS ${UNIT_TEST_LINK_LIBS}
        )

    hse_unit_test(
        NAME c1_kvcache_test
        LABELS c1
        SRCS c1/test/c1_kvcache_test.c
        INCLUDES ${UNIT_TEST_INCLUDE_DIRS}
        LINK_LIBS ${UNIT_TEST_LINK_LIBS}
        )

    hse_unit_test(
        NAME c1_misc_test
        LABEL c1
        SRCS
            c0/test/cn_mock.c
            c1/test/c1_misc_test.c
            c1/test/mock_mpool.c
        INCLUDES ${UNIT_TEST_INCLUDE_DIRS}
        LINK_LIBS ${UNIT_TEST_LINK_LIBS}
        )

    hse_unit_test(
        NAME logging_ut
        SRCS util/test/logging_ut.c
        INCLUDES ${UNIT_TEST_INCLUDE_DIRS}
        LINK_LIBS ${UNIT_TEST_LINK_LIBS}
        )

    hse_unit_test(
        NAME allocation_test
        SRCS util/test/allocation_test.c
        INCLUDES ${UNIT_TEST_INCLUDE_DIRS}
        LINK_LIBS ${UNIT_TEST_LINK_LIBS}
        )

    hse_unit_test(
        NAME bin_heap_test
        SRCS
            util/test/sample_element_source.c
            util/test/bin_heap_test.c
        INCLUDES ${UNIT_TEST_INCLUDE_DIRS}
        LINK_LIBS ${UNIT_TEST_LINK_LIBS}
        )

    hse_unit_test(
        NAME keylock_test
        SRCS util/test/keylock_test.c
        INCLUDES ${UNIT_TEST_INCLUDE_DIRS}
        LINK_LIBS ${UNIT_TEST_LINK_LIBS}
        )

    hse_unit_test(
        NAME table_test
        SRCS util/test/table_test.c
        INCLUDES ${UNIT_TEST_INCLUDE_DIRS}
        LINK_LIBS ${UNIT_TEST_LINK_LIBS}
        )

    hse_unit_test(
        NAME key_util_test
        SRCS util/test/key_util_test.c
        INCLUDES ${UNIT_TEST_INCLUDE_DIRS}
        LINK_LIBS ${UNIT_TEST_LINK_LIBS}
        )

#    # REVISIT: logging_test periodically fails
#    # because the syslog/vsyslog functions underlying hse_xlog() are
#    # intercepted to save log messages into a shared buffer. But
#    # there are multiple threads that use syslog/vsyslog, so by the
#    # time this message is parsed by process_json_payload(), the
#    # buffer could have been reused.
#
#    hse_unit_test(
#        NAME logging_test
#        SRCS
#            util/test/logging_test.c
#            util/test/mock_log.c
#        INCLUDES ${UNIT_TEST_INCLUDE_DIRS}
#        LINK_LIBS ${UNIT_TEST_LINK_LIBS}
#        )

#    # REVISIT: structured_logging_test periodically fails
#    # because the syslog/vsyslog functions underlying hse_xlog() are
#    # intercepted to save log messages into a shared buffer. But
#    # there are multiple threads that use syslog/vsyslog, so by the
#    # time this message is parsed by process_json_payload(), the
#    # buffer could have been reused.
#
#    hse_unit_test(
#        NAME structured_logging_test
#        SRCS util/test/structured_logging_test.c
#        INCLUDES ${UNIT_TEST_INCLUDE_DIRS}
#        LINK_LIBS ${UNIT_TEST_LINK_LIBS}
#        )

    hse_unit_test(
        NAME element_source_test
        SRCS
            util/test/sample_element_source.c
            util/test/element_source_test.c
        INCLUDES ${UNIT_TEST_INCLUDE_DIRS}
        LINK_LIBS ${UNIT_TEST_LINK_LIBS}
        )

    hse_unit_test(
        NAME timer_test
        SRCS util/test/timer_test.c
        INCLUDES ${UNIT_TEST_INCLUDE_DIRS}
        LINK_LIBS ${UNIT_TEST_LINK_LIBS}
        )

    hse_unit_test(
        NAME workqueue_test
        SRCS util/test/workqueue_test.c
        INCLUDES ${UNIT_TEST_INCLUDE_DIRS}
        LINK_LIBS ${UNIT_TEST_LINK_LIBS}
        )

    hse_unit_test(
        NAME parse_num_test
        SRCS util/test/parse_num_test.c
        INCLUDES ${UNIT_TEST_INCLUDE_DIRS}
        LINK_LIBS ${UNIT_TEST_LINK_LIBS}
        )

    hse_unit_test(
        NAME atomic_test
        SRCS
            util/test/atomic_test.c
            util/test/multithreaded_tester.c
        INCLUDES ${UNIT_TEST_INCLUDE_DIRS}
        LINK_LIBS ${UNIT_TEST_LINK_LIBS}
        )

    hse_unit_test(
        NAME param_test
        SRCS util/test/param_test.c
        INCLUDES ${UNIT_TEST_INCLUDE_DIRS}
        LINK_LIBS ${UNIT_TEST_LINK_LIBS}
        )

    hse_unit_test(
        NAME token_bucket_test
        SRCS util/test/token_bucket_test.c
        INCLUDES ${UNIT_TEST_INCLUDE_DIRS}
        LINK_LIBS ${UNIT_TEST_LINK_LIBS}
        )

    hse_unit_test(
        NAME delay_test
        SRCS util/test/delay_test.c
        INCLUDES ${UNIT_TEST_INCLUDE_DIRS}
        LINK_LIBS ${UNIT_TEST_LINK_LIBS}
        )

    hse_unit_test(
        NAME spinlock_test
        SRCS
            util/test/spinlock_test.c
            util/test/thread_tester.c
        INCLUDES ${UNIT_TEST_INCLUDE_DIRS}
        LINK_LIBS ${UNIT_TEST_LINK_LIBS}
        )

    hse_unit_test(
        NAME rwsem_test
        SRCS util/test/rwsem_test.c util/test/multithreaded_tester.c
        INCLUDES ${UNIT_TEST_INCLUDE_DIRS}
        LINK_LIBS ${UNIT_TEST_LINK_LIBS}
        )

    hse_unit_test(
        NAME rbtree_test
        SRCS util/test/rbtree_test.c
        INCLUDES ${UNIT_TEST_INCLUDE_DIRS}
        LINK_LIBS ${UNIT_TEST_LINK_LIBS}
        )

    hse_unit_test(
        NAME rest_api_test
        SRCS util/test/rest_api_test.c
        INCLUDES ${UNIT_TEST_INCLUDE_DIRS}
        DEPS libcurl-ext
        LINK_LIBS
            ${UNIT_TEST_LINK_LIBS}
            ${LIBCURL_LIBS}
            rt
            microhttpd
        )

    hse_unit_test(
        NAME rest_client_test
        SRCS util/test/rest_client_test.c
        INCLUDES ${UNIT_TEST_INCLUDE_DIRS}
        DEPS libcurl-ext
        LINK_LIBS
            ${UNIT_TEST_LINK_LIBS}
            ${LIBCURL_LIBS}
            rt
            microhttpd
        )

    hse_unit_test(
        NAME data_tree_test
        SRCS
            util/test/data_tree_test.c
            util/test/multithreaded_tester.c
        INCLUDES ${UNIT_TEST_INCLUDE_DIRS}
        LINK_LIBS ${UNIT_TEST_LINK_LIBS}
        )

    hse_unit_test(
         NAME perfc_test
         SRCS util/test/perfc_test.c
         INCLUDES ${UNIT_TEST_INCLUDE_DIRS}
         LINK_LIBS ${UNIT_TEST_LINK_LIBS} )

    hse_unit_test(
        NAME event_counter_test
        SRCS util/test/event_counter_test.c
        INCLUDES ${UNIT_TEST_INCLUDE_DIRS}
        LINK_LIBS ${UNIT_TEST_LINK_LIBS}
        )

    hse_unit_test(
        NAME config_test
        SRCS util/test/config_test.c
        INCLUDES ${UNIT_TEST_INCLUDE_DIRS}
        LINK_LIBS ${UNIT_TEST_LINK_LIBS} )

    hse_unit_test(
        NAME printbuf_test
        SRCS util/test/printbuf_test.c
        INCLUDES ${UNIT_TEST_INCLUDE_DIRS}
        LINK_LIBS ${UNIT_TEST_LINK_LIBS}
        )

    hse_unit_test(
        NAME json_test
        SRCS util/test/json_test.c
        INCLUDES ${UNIT_TEST_INCLUDE_DIRS}
        LINK_LIBS ${UNIT_TEST_LINK_LIBS}
        )

    hse_unit_test(
        NAME yaml_test
        SRCS util/test/yaml_test.c
        INCLUDES ${UNIT_TEST_INCLUDE_DIRS}
        LINK_LIBS ${UNIT_TEST_LINK_LIBS}
        )

    hse_unit_test(
        NAME hash_test
        SRCS util/test/hash_test.c
        INCLUDES ${UNIT_TEST_INCLUDE_DIRS}
        LINK_LIBS ${UNIT_TEST_LINK_LIBS}
        )

    hse_unit_test(
        NAME keycmp_test
        SRCS util/test/keycmp_test.c
        INCLUDES ${UNIT_TEST_INCLUDE_DIRS}
        LINK_LIBS ${UNIT_TEST_LINK_LIBS}
        )

    hse_unit_test(
        NAME bloom_filter_test
        SRCS util/test/bloom_filter_test.c
        INCLUDES ${UNIT_TEST_INCLUDE_DIRS}
        LINK_LIBS ${UNIT_TEST_LINK_LIBS}
        )

    hse_unit_test(
        NAME darray_test
        SRCS util/test/darray_test.c
        INCLUDES ${UNIT_TEST_INCLUDE_DIRS}
        LINK_LIBS ${UNIT_TEST_LINK_LIBS}
        )

    hse_unit_test(
        NAME program_name_test
        SRCS util/test/program_name_test.c
        INCLUDES ${UNIT_TEST_INCLUDE_DIRS}
        LINK_LIBS ${UNIT_TEST_LINK_LIBS}
        )

    hse_unit_test(
        NAME hse_err_test
        SRCS util/test/hse_err_test.c
        INCLUDES ${UNIT_TEST_INCLUDE_DIRS}
        LINK_LIBS ${UNIT_TEST_LINK_LIBS}
        )

    hse_unit_test(
        NAME mtx_pool_test
        SRCS util/test/mtx_pool_test.c
        INCLUDES ${UNIT_TEST_INCLUDE_DIRS}
        LINK_LIBS ${UNIT_TEST_LINK_LIBS}
        )

    hse_unit_test(
        NAME log2_test
        SRCS util/test/log2_test.c
        INCLUDES ${UNIT_TEST_INCLUDE_DIRS}
        LINK_LIBS ${UNIT_TEST_LINK_LIBS}
        )

    hse_unit_test(
        NAME cheap_test
        SRCS
            util/test/cheap_test.c
            util/test/cheap_testlib.c
        INCLUDES ${UNIT_TEST_INCLUDE_DIRS}
        LINK_LIBS ${UNIT_TEST_LINK_LIBS}
        )

    hse_unit_test(
        NAME seqno_test
        SRCS util/test/seqno_test.c
        INCLUDES ${UNIT_TEST_INCLUDE_DIRS}
        LINK_LIBS ${UNIT_TEST_LINK_LIBS}
        )

    hse_unit_test(
        NAME event_timer_test
        SRCS util/test/event_timer_test.c
        INCLUDES ${UNIT_TEST_INCLUDE_DIRS}
        LINK_LIBS ${UNIT_TEST_LINK_LIBS}
        )

    hse_unit_test(
        NAME list_test
        SRCS util/test/list_test.c
        INCLUDES ${UNIT_TEST_INCLUDE_DIRS}
        LINK_LIBS ${UNIT_TEST_LINK_LIBS}
        )

    hse_unit_test(
        NAME bonsai_tree_test
        SRCS util/test/bonsai_tree_test.c
        INCLUDES ${UNIT_TEST_INCLUDE_DIRS}
        LINK_LIBS ${UNIT_TEST_LINK_LIBS} urcu-bp
        )

    hse_unit_test(
        NAME parser_test
        SRCS util/test/parser_test.c
        INCLUDES ${UNIT_TEST_INCLUDE_DIRS}
        LINK_LIBS ${UNIT_TEST_LINK_LIBS}
        )

    hse_unit_test(
        NAME hlog_unit_test
        SRCS util/test/hlog_unit_test.c
        INCLUDES ${UNIT_TEST_INCLUDE_DIRS}
        LINK_LIBS ${UNIT_TEST_LINK_LIBS}
        )

    hse_unit_test(
        NAME fmt_test
        SRCS util/test/fmt_test.c
        INCLUDES ${UNIT_TEST_INCLUDE_DIRS}
        LINK_LIBS ${UNIT_TEST_LINK_LIBS}
        )

    hse_unit_test(
        NAME mclass_policy_test
        SRCS kvdb/test/mclass_policy_test.c
        INCLUDES ${UNIT_TEST_INCLUDE_DIRS}
        LINK_DIRS
            ${MPOOL_LIB_DIR}
            ${BLKID_LIB_DIR}
        LINK_LIBS ${UNIT_TEST_LINK_LIBS}
        )

    hse_unit_test(
        NAME vlb_test
        SRCS util/test/vlb_test.c
        INCLUDES ${UNIT_TEST_INCLUDE_DIRS}
        LINK_LIBS ${UNIT_TEST_LINK_LIBS}
        )

    hse_unit_test(
        NAME compression_test
        SRCS util/test/compression_test.c
        INCLUDES ${UNIT_TEST_INCLUDE_DIRS}
        LINK_LIBS
            ${UNIT_TEST_LINK_LIBS}
        )

    hse_unit_test(
        NAME xrand_test
        SRCS
            util/test/xrand_test.c
        INCLUDES ${UNIT_TEST_INCLUDE_DIRS}
        LINK_LIBS ${UNIT_TEST_LINK_LIBS}
        )

endif()
