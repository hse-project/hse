/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2021 Micron Technology, Inc.  All rights reserved.
 */

#include <stdlib.h>
#include <uuid/uuid.h>

#include <hse_util/logging.h>
#include <hse_util/event_counter.h>
#include <hse_util/hse_err.h>
#include <hse_util/string.h>

#include <hse/hse.h>
#include <mpool/mpool_internal.h>

#include "mpool.h"

#define UUID_STRLEN    36

merr_t
mpool_open2(const char *name, const struct hse_params *params, struct mpool **handle)
{
    struct mpool *mp;

    const char *mc_key[MCID_MAX] = {"kvdb.capdir", "kvdb.stgdir"};
    merr_t      err;
    int         i;

    *handle = NULL;

    if (ev(!params || !name || !handle))
        return merr(EINVAL);

    mp = calloc(1, sizeof(*mp));
    if (ev(!mp))
        return merr(ENOMEM);

    for (i = MCID_CAPACITY; i < MCID_MAX; i++) {
        char dpath[PATH_MAX];

        if (hse_params_get(params, mc_key[i], dpath, sizeof(dpath), NULL)) {
            if (dpath[0] != '\0') {
                err = mclass_open(mp, i, dpath, &mp->mc[i]);
                if (ev(err)) {
                    hse_log(HSE_ERR "Malformed storage path for mclass %s", mc_key[i]);
                    goto errout;
                }
            }
        }
    }

    strlcpy(mp->name, name, sizeof(mp->name));

    *handle = mp;

    return 0;

errout:
    while (i-- > MCID_CAPACITY)
        mclass_close(mp->mc[i]);

    free(mp);

    return err;
}

merr_t
mpool_close2(struct mpool *mp)
{
    merr_t err = 0;
    int i;

    if (ev(!mp))
        return merr(EINVAL);

    for (i = MCID_MAX - 1; i >= MCID_CAPACITY; i--) {
        err = mclass_close(mp->mc[i]);
        if (err)
            hse_log(HSE_ERR "Closing mclass id %d failed", i);
    }

    free(mp);

    return err;
}

merr_t
mpool_destroy2(struct mpool *mp)
{
    int i;

    if (ev(!mp))
        return merr(EINVAL);

    for (i = MCID_MAX - 1; i >= MCID_CAPACITY; i--)
        mclass_destroy(mp->mc[i]);

    free(mp);

    return 0;
}

merr_t
mpool_params_get2(struct mpool *mp, struct mpool_params *params)
{
    char ubuf[UUID_STRLEN + 1];
    merr_t err;

    memset(params, 0, sizeof(*params));

    /* Fill utype if present. */
    err = mclass_params_get(mp->mc[MCID_CAPACITY], "utype", (char *)ubuf, sizeof(ubuf) - 1);
    if (!err) {
        ubuf[UUID_STRLEN] = '\0';
        uuid_parse((const char *)ubuf, params->mp_utype);
    }

    return 0;
}

merr_t
mpool_params_set2(struct mpool *mp, struct mpool_params *params)
{
    if (!uuid_is_null(params->mp_utype)) {
        char ubuf[UUID_STRLEN + 1];

        uuid_unparse(params->mp_utype, ubuf);

        return mclass_params_set(mp->mc[MCID_CAPACITY], "utype",
                                 (const char *)ubuf, sizeof(ubuf) - 1);
    }

    return 0;
}
