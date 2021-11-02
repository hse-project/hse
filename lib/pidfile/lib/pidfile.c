/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2021 Micron Technology, Inc.  All rights reserved.
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

#include <pidfile/pidfile.h>

int
pidfile_serialize(struct pidfh *pfh, const struct pidfile *content)
{
    assert(pfh);
    assert(content);

    cJSON *root = NULL, *socket = NULL;
    char * str = NULL;
    int    rc = 0;

    root = cJSON_CreateObject();
    if (!root) {
        rc = ENOMEM;
        goto out;
    }
    if (!cJSON_AddNumberToObject(root, "pid", (double)content->pid)) {
        rc = ENOMEM;
        goto out;
    }
    if (!cJSON_AddStringToObject(root, "alias", content->alias)) {
        rc = ENOMEM;
        goto out;
    }
    socket = cJSON_AddObjectToObject(root, "socket");
    if (!socket) {
        rc = ENOMEM;
        goto out;
    }
    if (content->socket.path[0] == '\0') {
        if (!cJSON_AddNullToObject(socket, "path")) {
            rc = ENOMEM;
            goto out;
        }
    } else {
        if (!cJSON_AddStringToObject(socket, "path", content->socket.path)) {
            rc = ENOMEM;
            goto out;
        }
    }

    str = cJSON_Print(root);
    if (!str) {
        rc = ENOMEM;
        goto out;
    }

    if (write(pidfile_fileno(pfh), str, strlen(str)) == -1) {
        rc = errno;
        goto out;
    }

out:
    cJSON_free(str);
    cJSON_Delete(root);

    return rc;
}

int
pidfile_deserialize(const char *home, struct pidfile *content)
{
    assert(home);
    assert(content);

    FILE *      pidf = NULL;
    cJSON *     root = NULL, *pid = NULL, *alias = NULL, *socket = NULL, *socket_path = NULL;
    char *      str = NULL;
    int         rc = 0;
    int         fd;
    size_t      n = 0;
    char        pidfile_path[PATH_MAX];
    struct stat st;

    n = snprintf(pidfile_path, sizeof(pidfile_path), "%s/" PIDFILE_NAME, home);
    if (n >= sizeof(pidfile_path)) {
        rc = ENAMETOOLONG;
        goto out;
    }

    pidf = fopen(pidfile_path, "r");
    if (!pidf) {
        rc = errno;
        goto out;
    }

    fd = fileno(pidf);
    if (fd == -1) {
        rc = errno;
        goto out;
    }

    if (fstat(fd, &st) == -1) {
        rc = errno;
        goto out;
    }

    str = malloc(st.st_size + 1);
    if (!str) {
        rc = ENOMEM;
        goto out;
    }

    n = fread(str, st.st_size, 1, pidf);
    if (n != 1 || ferror(pidf)) {
        rc = EIO;
        goto out;
    }

    str[st.st_size] = '\0';

    root = cJSON_ParseWithLength(str, st.st_size);
    if (!root) {
        if (cJSON_GetErrorPtr()) {
            rc = EPROTO;
        } else {
            rc = ENOMEM;
        }
        goto out;
    }
    pid = cJSON_GetObjectItemCaseSensitive(root, "pid");
    if (!pid || !cJSON_IsNumber(pid)) {
        rc = EINVAL;
        goto out;
    }
    alias = cJSON_GetObjectItemCaseSensitive(root, "alias");
    if (!alias || !cJSON_IsString(alias)) {
        rc = EINVAL;
        goto out;
    }
    socket = cJSON_GetObjectItemCaseSensitive(root, "socket");
    if (!socket || !cJSON_IsObject(socket)) {
        rc = EINVAL;
        goto out;
    }
    socket_path = cJSON_GetObjectItemCaseSensitive(socket, "path");
    if (!socket_path || !(cJSON_IsString(socket_path) || cJSON_IsNull(socket_path))) {
        rc = EINVAL;
        goto out;
    }

    content->pid = (pid_t)cJSON_GetNumberValue(pid);
    n = strlcpy(content->alias, cJSON_GetStringValue(alias), sizeof(content->alias));
    if (n >= sizeof(content->alias)) {
        rc = ENAMETOOLONG;
        goto out;
    }
    if (cJSON_IsNull(socket_path)) {
        memset(content->socket.path, 0, sizeof(content->socket.path));
    } else {
        n = strlcpy(
            content->socket.path, cJSON_GetStringValue(socket_path), sizeof(content->socket.path));
        if (n >= sizeof(content->socket.path)) {
            rc = ENAMETOOLONG;
            goto out;
        }
    }

out:
    if (str)
        free(str);
    cJSON_Delete(root);
    if (pidf && fclose(pidf) && !rc)
        rc = errno;

    return rc;
}
