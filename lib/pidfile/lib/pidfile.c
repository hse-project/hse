/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021-2022 Micron Technology, Inc.  All rights reserved.
 */

#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <unistd.h>
#include <sys/stat.h>

#include <cjson/cJSON.h>
#include <bsd/string.h>
#include <bsd/libutil.h>

#include <hse/error/merr.h>
#include <hse/pidfile/pidfile.h>

merr_t
pidfile_serialize(struct pidfh *pfh, const struct pidfile *content)
{
    merr_t err = 0;
    char * str = NULL;
    cJSON *root = NULL, *rest = NULL;

    if (!pfh || !content)
        return merr(EINVAL);

    root = cJSON_CreateObject();
    if (!root)
        return merr(ENOMEM);

    if (!cJSON_AddNumberToObject(root, "pid", (double)content->pid)) {
        err = merr(ENOMEM);
        goto out;
    }
    if (!cJSON_AddStringToObject(root, "alias", content->alias)) {
        err = merr(ENOMEM);
        goto out;
    }
    rest = cJSON_AddObjectToObject(root, "rest");
    if (!rest) {
        err = merr(ENOMEM);
        goto out;
    }
    if (content->rest.socket_path[0] == '\0') {
        if (!cJSON_AddNullToObject(rest, "socket_path")) {
            err = merr(ENOMEM);
            goto out;
        }
    } else {
        if (!cJSON_AddStringToObject(rest, "socket_path", content->rest.socket_path)) {
            err = merr(ENOMEM);
            goto out;
        }
    }

    str = cJSON_Print(root);
    if (!str) {
        err = merr(ENOMEM);
        goto out;
    }

    if (write(pidfile_fileno(pfh), str, strlen(str)) == -1) {
        err = merr(errno);
        goto out;
    }

out:
    cJSON_free(str);
    cJSON_Delete(root);

    return err;
}

merr_t
pidfile_deserialize(const char *home, struct pidfile *content)
{
    int fd;
    size_t n = 0;
    merr_t err = 0;
    struct stat st;
    FILE *pidf = NULL;
    char *str = NULL;
    char pidfile_path[PATH_MAX];
    cJSON *root = NULL, *pid = NULL, *alias = NULL, *rest = NULL, *socket_path = NULL;

    if (!home || !content)
        return merr(EINVAL);

    n = snprintf(pidfile_path, sizeof(pidfile_path), "%s/" PIDFILE_NAME, home);
    if (n >= sizeof(pidfile_path))
        return merr(ENAMETOOLONG);

    pidf = fopen(pidfile_path, "r");
    if (!pidf) {
        err = merr(errno);
        goto out;
    }

    fd = fileno(pidf);
    if (fd == -1) {
        err = merr(errno);
        goto out;
    }

    if (fstat(fd, &st) == -1) {
        err = merr(errno);
        goto out;
    }

    str = malloc(st.st_size + 1);
    if (!str) {
        err = merr(ENOMEM);
        goto out;
    }

    n = fread(str, st.st_size, 1, pidf);
    if (n != 1 || ferror(pidf)) {
        err = merr(EIO);
        goto out;
    }

    str[st.st_size] = '\0';

    root = cJSON_ParseWithLength(str, st.st_size);
    if (!root) {
        if (cJSON_GetErrorPtr()) {
            err = merr(EPROTO);
        } else {
            err = merr(ENOMEM);
        }
        goto out;
    }
    pid = cJSON_GetObjectItemCaseSensitive(root, "pid");
    if (!pid || !cJSON_IsNumber(pid)) {
        err = merr(EINVAL);
        goto out;
    }
    alias = cJSON_GetObjectItemCaseSensitive(root, "alias");
    if (!alias || !cJSON_IsString(alias)) {
        err = merr(EINVAL);
        goto out;
    }
    rest = cJSON_GetObjectItemCaseSensitive(root, "rest");
    if (!rest || !cJSON_IsObject(rest)) {
        err = merr(EINVAL);
        goto out;
    }
    socket_path = cJSON_GetObjectItemCaseSensitive(rest, "socket_path");
    if (!socket_path || !(cJSON_IsString(socket_path) || cJSON_IsNull(socket_path))) {
        err = merr(EINVAL);
        goto out;
    }

    content->pid = (pid_t)cJSON_GetNumberValue(pid);
    n = strlcpy(content->alias, cJSON_GetStringValue(alias), sizeof(content->alias));
    if (n >= sizeof(content->alias)) {
        err = merr(ENAMETOOLONG);
        goto out;
    }
    if (cJSON_IsNull(socket_path)) {
        memset(content->rest.socket_path, 0, sizeof(content->rest.socket_path));
    } else {
        n = strlcpy(
            content->rest.socket_path, cJSON_GetStringValue(socket_path), sizeof(content->rest.socket_path));
        if (n >= sizeof(content->rest.socket_path)) {
            err = merr(ENAMETOOLONG);
            goto out;
        }
    }

out:
    free(str);
    cJSON_Delete(root);
    if (pidf && fclose(pidf) && !err)
        err = merr(errno);

    return err;
}
