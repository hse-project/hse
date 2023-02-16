/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2015 Micron Technology, Inc.
 */

#include <hse/ikvdb/kvdb_rparams.h>
#include <hse/ikvdb/throttle.h>
#include <hse/ikvdb/throttle_perfc.h>
#include <hse/util/platform.h>
#include <hse/util/xrand.h>

#include <hse/test/mock/alloc_tester.h>
#include <hse/test/mock/api.h>
#include <hse/test/mtf/framework.h>

#define KMIN 1

struct throttle throttlebuf;
struct throttle *t = &throttlebuf;
const int sc = THROTTLE_SENSOR_CNT;
struct throttle_sensor *sv[THROTTLE_SENSOR_CNT];
struct kvdb_rparams kvdb_rp;

void
init(void)
{
    int i;

    kvdb_rp = kvdb_rparams_defaults();

    t = &throttlebuf;
    throttle_init(t, &kvdb_rp, __func__);
    for (i = 0; i < sc; i++)
        sv[i] = throttle_sensor(t, i);
    throttle_init_params(t, &kvdb_rp);

    /* throttle_update() is periodicaly called by the jiffy timer,
     * so we must unregister it so that these tests can directly
     * call it.
     */
    hse_timer_cb_register(NULL, NULL, 0);
}

int
pre_collection(struct mtf_test_info *info)
{
    return 0;
}

static int
pre_test(struct mtf_test_info *ti)
{
    return 0;
}

MTF_BEGIN_UTEST_COLLECTION_PRE(test, pre_collection)

MTF_DEFINE_UTEST_PRE(test, t_init, pre_test)
{
    struct throttle thr;
    int i;

    for (i = 0; i <= 1; i++) {
        kvdb_rp = kvdb_rparams_defaults();

        if (i == 1) {
            mapi_inject(mapi_idx_perfc_alloc_impl, -1);
            mapi_inject(mapi_idx_perfc_ivl_create, -1);
        }

        throttle_init(&thr, &kvdb_rp, __func__);
        throttle_fini(&thr);

        mapi_inject_unset(mapi_idx_perfc_alloc_impl);
        mapi_inject_unset(mapi_idx_perfc_ivl_create);
    }
}

MTF_DEFINE_UTEST_PRE(test, t_basic, pre_test)
{
    int i, sval;

    kvdb_rp = kvdb_rparams_defaults();

    t = &throttlebuf;
    throttle_init(t, &kvdb_rp, __func__);
    throttle_debug(t);

    /* delay should be 0 after init */
    ASSERT_EQ(throttle_delay(t), 0);

    throttle_init_params(t, &kvdb_rp);

    /* delay should be THROTTLE_DELAY_START_AUTO after init params */
    ASSERT_EQ(THROTTLE_DELAY_START_AUTO, throttle_delay(t));

    /* get sensors */
    for (i = 0; i < sc; i++) {
        sv[i] = throttle_sensor(t, i);
        ASSERT_NE(sv[i], NULL);
    }

    /* invalid sensor number --> NULL */
    ASSERT_EQ(throttle_sensor(t, sc), NULL);

    /* delay should still be THROTTLE_DELAY_START_AUTO after sensor retrieved */
    ASSERT_EQ(THROTTLE_DELAY_START_AUTO, throttle_delay(t));

    /* sensor values should be 0 */
    for (i = 0; i < sc; i++) {
        sval = throttle_sensor_get(sv[i]);
        ASSERT_EQ(sval, 0);
    }
}

MTF_DEFINE_UTEST_PRE(test, t_dur_params, pre_test)
{
    int i, sval;

    kvdb_rp = kvdb_rparams_defaults();
    kvdb_rp.dur_throttle_lo_th = kvdb_rp.dur_throttle_hi_th = 50;

    t = &throttlebuf;

    throttle_init(t, &kvdb_rp, __func__);
    throttle_init_params(t, &kvdb_rp);

    /* get sensors */
    for (i = 0; i < sc; i++) {
        sv[i] = throttle_sensor(t, i);
        ASSERT_NE(sv[i], NULL);
    }

    /* sensor values should be 0 */
    for (i = 0; i < sc; i++) {
        sval = throttle_sensor_get(sv[i]);
        ASSERT_EQ(sval, 0);
    }

    throttle_fini(t);

    kvdb_rp = kvdb_rparams_defaults();

    throttle_init(t, &kvdb_rp, __func__);
    throttle_init_params(t, &kvdb_rp);

    /* get sensors */
    for (i = 0; i < sc; i++) {
        sv[i] = throttle_sensor(t, i);
        ASSERT_NE(sv[i], NULL);
    }

    /* sensor values should be 0 */
    for (i = 0; i < sc; i++) {
        sval = throttle_sensor_get(sv[i]);
        ASSERT_EQ(sval, 0);
    }

    throttle_fini(t);

    kvdb_rp = kvdb_rparams_defaults();
    kvdb_rp.dur_throttle_lo_th = 0;

    throttle_init(t, &kvdb_rp, __func__);
    throttle_init_params(t, &kvdb_rp);

    /* get sensors */
    for (i = 0; i < sc; i++) {
        sv[i] = throttle_sensor(t, i);
        ASSERT_NE(sv[i], NULL);
    }

    /* sensor values should be 0 */
    for (i = 0; i < sc; i++) {
        sval = throttle_sensor_get(sv[i]);
        ASSERT_EQ(sval, 0);
    }

    throttle_fini(t);

    kvdb_rp = kvdb_rparams_defaults();
    kvdb_rp.throttle_disable = 1;

    throttle_init(t, &kvdb_rp, __func__);
    throttle_init_params(t, &kvdb_rp);

    throttle_fini(t);

    /* Set a slow throttle update rate */
    kvdb_rp = kvdb_rparams_defaults();
    kvdb_rp.throttle_update_ns = 1000000UL * 5000UL;

    throttle_init(t, &kvdb_rp, __func__);
    throttle_init_params(t, &kvdb_rp);

    throttle_fini(t);
}

MTF_DEFINE_UTEST_PRE(test, t_range, pre_test)
{
    int ranges[5] = { 750, 1001, 1500, 1800, 2001 };
    int i, value1, value2, range;

    init();

    for (i = 0; i < 500000; i++) {
        range = ranges[rand() % 5];

        value1 = rand() % range;
        value2 = rand() % range;

        throttle_sensor_set(sv[0], value1);
        throttle_sensor_set(sv[1], value2);
        throttle_update(t);
        throttle_debug(t);
        throttle_reduce_debug(t, value2, 0);
    }

    for (i = 0; i < 500000; i++) {
        int index = rand() % 5;
        int vmin = (index > 0) ? ranges[index - 1] : 0;
        int vmax = ranges[index];
        uint range = vmax - vmin;

        value1 = vmin + rand() % range;
        value2 = vmin + rand() % range;

        throttle_sensor_set(sv[0], value1);
        throttle_sensor_set(sv[1], value2);
        throttle_update(t);
        throttle_debug(t);
        throttle_reduce_debug(t, value2, 0);
    }

    /* Exercise rapid increase in throttling. */
    for (i = 0; i < 100000; i++) {
        range = ranges[rand() % 5];

        value1 = rand() % range;
        value2 = rand() % range;

        throttle_sensor_set(sv[0], value1);
        throttle_sensor_set(sv[1], value2);
        throttle_update(t);
        throttle_debug(t);
        throttle_reduce_debug(t, value2, 0);
    }

    /* Exercise multiplicative decrease */
    range = THROTTLE_SENSOR_SCALE / 2;
    for (i = 0; i < 100000; i++) {
        value1 = rand() % range;
        value2 = rand() % range;

        throttle_sensor_set(sv[0], value1);
        throttle_sensor_set(sv[1], value2);
        throttle_update(t);
        throttle_debug(t);
        throttle_reduce_debug(t, value2, 0);
    }
}

MTF_END_UTEST_COLLECTION(test);
