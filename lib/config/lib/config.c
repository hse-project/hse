/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021-2022 Micron Technology, Inc.  All rights reserved.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cjson/cJSON.h>

#include <hse/config/config.h>
#include <hse/error/merr.h>
#include <hse/logging/logging.h>

merr_t
config_open(const char *const path, config_validator_t validate, cJSON **const config)
{
    int fd;
    struct stat st;
    merr_t err = 0;
    char *str = NULL;
    cJSON *impl = NULL;

    if (!path || !config)
        return merr(EINVAL);

    *config = NULL;

    fd = open(path, O_RDONLY);
    if (fd == -1) {
        err = merr(errno);
        log_errx("Failed to open %s", err, path);
        return err;
    }

    if (fstat(fd, &st) == -1) {
        err = merr(errno);
        log_errx("Failed to get the size of %s", err, path);
        goto out;
    }

    str = malloc(st.st_size);
    if (!str) {
        err = merr(ENOMEM);
        goto out;
    }

    if (read(fd, str, st.st_size) == -1) {
        err = merr(errno);
        log_errx("Failed to read %s", err, path);
        goto out;
    }

    impl = cJSON_ParseWithLength(str, st.st_size);
    if (!impl) {
        if (cJSON_GetErrorPtr()) {
            log_err("%s is not a valid config file: %s", path, cJSON_GetErrorPtr());
            err = merr(EINVAL);
        } else {
            err = merr(ENOMEM);
        }
        goto out;
    }

    if (!cJSON_IsObject(impl)) {
        log_err("%s is not a valid config file", path);
        err = merr(EINVAL);
        goto out;
    }

    err = validate ? validate(impl) : 0;
    if (err) {
        log_errx("Failed to validate %s", err, path);
        goto out;
    }

    *config = impl;

out:
    free(str);
    close(fd);
    if (err)
        cJSON_Delete(impl);

    return err;
}
