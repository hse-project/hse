/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
 */

#include <errno.h>

#include <bsd/string.h>
#include <cjson/cJSON.h>
#include <yaml.h>

#include <hse/hse.h>
#include <hse_util/invariant.h>
#include <hse_util/rest_client.h>

#include <pidfile/pidfile.h>

#define MEDIA_CLASS_KEY     "media_class"
#define PATH_KEY            "path"
#define USED_BYTES_KEY      "used_bytes"
#define ALLOCATED_BYTES_KEY "allocated_bytes"

static const char *const media_classes[] = {
    HSE_MCLASS_CAPACITY_NAME, HSE_MCLASS_STAGING_NAME
};

#define NUM_MCLASSES (sizeof(media_classes) / sizeof(media_classes[0]))

int
hse_storage_info(const char *const kvdb_home)
{
    hse_err_t               err;
    struct hse_kvdb *       kvdb = NULL;
    struct hse_mclass_info  info[NUM_MCLASSES];
    yaml_emitter_t          emitter = {};
    yaml_event_t            event;
    int                     rc = 0;
    struct pidfile          content;
    char                    url[128];
    char                    buf[1024];
    bool                    configured[NUM_MCLASSES] = {};
    cJSON *                 root;
    HSE_MAYBE_UNUSED size_t n;

    INVARIANT(kvdb_home);
    INVARIANT(media_class);

    err = hse_kvdb_open(kvdb_home, 0, NULL, &kvdb);
    if (!err) {
        for (size_t i = 0; i < NUM_MCLASSES; i++) {
            err = hse_kvdb_mclass_info_get(kvdb, media_classes[i], &info[i]);
            if (err) {
                if (hse_err_to_errno(err) == ENOENT)
                    continue;

                goto out;
            }

            configured[i] = true;
        }
    } else if (err && hse_err_to_errno(err) == EBUSY) {
        rc = pidfile_deserialize(kvdb_home, &content);
        if (rc)
            goto out;

        for (size_t i = 0; i < NUM_MCLASSES; i++) {
            struct hse_mclass_info *data = &info[i];

            rc = snprintf(
                url, sizeof(url), "kvdb/%s/mclass/%s/info", content.alias, media_classes[i]);
            if (rc < 0) {
                rc = EBADMSG;
                goto out;
            }

            assert(rc < sizeof(url));

            err = curl_get(url, content.socket.path, buf, sizeof(buf));
            if (err)
                goto out;

            /* Because of issues with the REST server, and the way this
             * curl_get() function is implemented, I cannot return what would
             * ideally be a 404 status in which I could find out whether the
             * media class was configured or not. To overcome this, if the
             * following parse fails, then we assume that it is because no data
             * was written into the buffer, meaning the media class was not
             * configured.
             */
            root = cJSON_Parse(buf);
            if (!root) {
                if (cJSON_GetErrorPtr()) {
                    continue;
                } else {
                    rc = ENOMEM;
                    goto out;
                }
            }

            configured[i] = true;

            n = strlcpy(
                data->mi_path, cJSON_GetStringValue(cJSON_GetObjectItemCaseSensitive(root, "path")),
                sizeof(data->mi_path));
            assert(n < sizeof(data->mi_path));
            data->mi_allocated_bytes = cJSON_GetNumberValue(
                cJSON_GetObjectItemCaseSensitive(root, "allocated_bytes"));
            data->mi_used_bytes = cJSON_GetNumberValue(
                cJSON_GetObjectItemCaseSensitive(root, "used_bytes"));
        }
    } else {
        return hse_err_to_errno(err);
    }

    if (!yaml_emitter_initialize(&emitter)) {
        rc = EIO;
        goto out;
    }

    yaml_emitter_set_output_file(&emitter, stdout);

    yaml_stream_start_event_initialize(&event, YAML_UTF8_ENCODING);
    if (!yaml_emitter_emit(&emitter, &event)) {
        rc = EIO;
        goto out;
    }

    yaml_document_start_event_initialize(&event, NULL, NULL, NULL, 0);
    if (!yaml_emitter_emit(&emitter, &event)) {
        rc = EIO;
        goto out;
    }

    yaml_sequence_start_event_initialize(
        &event, NULL, (yaml_char_t *)YAML_SEQ_TAG, 1, YAML_ANY_SEQUENCE_STYLE);
    if (!yaml_emitter_emit(&emitter, &event)) {
        rc = EIO;
        goto out;
    }

    for (size_t i = 0; i < NUM_MCLASSES; i++) {
        if (!configured[i])
            continue;

        yaml_mapping_start_event_initialize(
            &event, NULL, (yaml_char_t *)YAML_MAP_TAG, 1, YAML_ANY_MAPPING_STYLE);
        if (!yaml_emitter_emit(&emitter, &event)) {
            rc = EIO;
            goto out;
        }

        yaml_scalar_event_initialize(
            &event,
            NULL,
            (yaml_char_t *)YAML_STR_TAG,
            (yaml_char_t *)MEDIA_CLASS_KEY,
            sizeof(MEDIA_CLASS_KEY) - 1,
            1,
            0,
            YAML_PLAIN_SCALAR_STYLE);
        if (!yaml_emitter_emit(&emitter, &event)) {
            rc = EIO;
            goto out;
        }

        yaml_scalar_event_initialize(
            &event,
            NULL,
            (yaml_char_t *)YAML_STR_TAG,
            (yaml_char_t *)media_classes[i],
            strlen(media_classes[i]),
            1,
            0,
            YAML_PLAIN_SCALAR_STYLE);
        if (!yaml_emitter_emit(&emitter, &event)) {
            rc = EIO;
            goto out;
        }

        yaml_scalar_event_initialize(
            &event,
            NULL,
            (yaml_char_t *)YAML_STR_TAG,
            (yaml_char_t *)PATH_KEY,
            sizeof(PATH_KEY) - 1,
            1,
            0,
            YAML_PLAIN_SCALAR_STYLE);
        if (!yaml_emitter_emit(&emitter, &event)) {
            rc = EIO;
            goto out;
        }

        yaml_scalar_event_initialize(
            &event,
            NULL,
            (yaml_char_t *)YAML_STR_TAG,
            (yaml_char_t *)info[i].mi_path,
            strnlen(info[i].mi_path, sizeof(info[i].mi_path)),
            1,
            0,
            YAML_PLAIN_SCALAR_STYLE);
        if (!yaml_emitter_emit(&emitter, &event)) {
            rc = EIO;
            goto out;
        }

        yaml_scalar_event_initialize(
            &event,
            NULL,
            (yaml_char_t *)YAML_STR_TAG,
            (yaml_char_t *)ALLOCATED_BYTES_KEY,
            sizeof(ALLOCATED_BYTES_KEY) - 1,
            1,
            0,
            YAML_PLAIN_SCALAR_STYLE);
        if (!yaml_emitter_emit(&emitter, &event)) {
            rc = EIO;
            goto out;
        }

        rc = snprintf(buf, sizeof(buf), "%lu", info[i].mi_allocated_bytes);
        if (rc < 0) {
            return EBADMSG;
        } else if (rc >= sizeof(buf)) {
            return EMSGSIZE;
        }

        yaml_scalar_event_initialize(
            &event,
            NULL,
            (yaml_char_t *)YAML_STR_TAG,
            (yaml_char_t *)buf,
            strnlen(buf, sizeof(buf)),
            1,
            0,
            YAML_PLAIN_SCALAR_STYLE);
        if (!yaml_emitter_emit(&emitter, &event)) {
            rc = EIO;
            goto out;
        }

        yaml_scalar_event_initialize(
            &event,
            NULL,
            (yaml_char_t *)YAML_STR_TAG,
            (yaml_char_t *)USED_BYTES_KEY,
            sizeof(USED_BYTES_KEY) - 1,
            1,
            0,
            YAML_PLAIN_SCALAR_STYLE);
        if (!yaml_emitter_emit(&emitter, &event)) {
            rc = EIO;
            goto out;
        }

        rc = snprintf(buf, sizeof(buf), "%lu", info[i].mi_used_bytes);
        if (rc < 0) {
            rc = EBADMSG;
            goto out;
        } else if (rc >= sizeof(buf)) {
            rc = EMSGSIZE;
            goto out;
        }

        yaml_scalar_event_initialize(
            &event,
            NULL,
            (yaml_char_t *)YAML_STR_TAG,
            (yaml_char_t *)buf,
            strnlen(buf, sizeof(buf)),
            1,
            0,
            YAML_PLAIN_SCALAR_STYLE);
        if (!yaml_emitter_emit(&emitter, &event)) {
            rc = EIO;
            goto out;
        }

        yaml_mapping_end_event_initialize(&event);
        if (!yaml_emitter_emit(&emitter, &event)) {
            rc = EIO;
            goto out;
        }
    }

    yaml_sequence_end_event_initialize(&event);
    if (!yaml_emitter_emit(&emitter, &event)) {
        rc = EIO;
        goto out;
    }

    yaml_document_end_event_initialize(&event, 0);
    if (!yaml_emitter_emit(&emitter, &event)) {
        rc = EIO;
        goto out;
    }

    yaml_stream_end_event_initialize(&event);
    if (!yaml_emitter_emit(&emitter, &event)) {
        rc = EIO;
        goto out;
    }

out:
    yaml_emitter_delete(&emitter);

    if (kvdb)
        hse_kvdb_close(kvdb);

    return rc ? rc : hse_err_to_errno(err);
}
