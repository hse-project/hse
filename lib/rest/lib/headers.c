/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2022 Micron Technology, Inc.
 */

#include <assert.h>
#include <event.h>
#include <string.h>

#include <event2/http.h>
#include <sys/queue.h>

#include <hse/error/merr.h>
#include <hse/rest/headers.h>
#include <hse/util/compiler.h>

const char *
rest_headers_get(const struct rest_headers * const headers, const char * const key)
{
    struct evkeyval *header;

    TAILQ_FOREACH(header, (struct evkeyvalq *)headers, next) {
        if (strcasecmp(header->key, key) == 0)
            return header->value;
    }

    return NULL;
}

merr_t
rest_headers_set(
    struct rest_headers * const headers,
    const char * const key,
    const char * const value)
{
    int rc;

    rc = evhttp_add_header((struct evkeyvalq *)headers, key, value);
    if (rc == -1)
        return merr(ENOMEM);

    return 0;
}
