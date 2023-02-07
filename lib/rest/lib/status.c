/* SPDX-License-Identifier: Apache-2.0 OR MIT
 *
 * SPDX-FileCopyrightText: Copyright 2022 Micron Technology, Inc.
 */

#include <assert.h>
#include <stdbool.h>
#include <stdlib.h>

#include <hse/rest/status.h>

#include "status.h"

const char *
status_to_reason(const enum rest_status status)
{
    switch (status) {
    case REST_STATUS_OK:
        return "OK";
    case REST_STATUS_CREATED:
        return "Created";
    case REST_STATUS_ACCEPTED:
        return "Accpeted";
    case REST_STATUS_BAD_REQUEST:
        return "Bad Request";
    case REST_STATUS_FORBIDDEN:
        return "Forbidden";
    case REST_STATUS_NOT_FOUND:
        return "Not Found";
    case REST_STATUS_METHOD_NOT_ALLOWED:
        return "Method Not Allowed";
    case REST_STATUS_LOCKED:
        return "Locked";
    case REST_STATUS_INTERNAL_SERVER_ERROR:
        return "Internal Server Error";
    case REST_STATUS_NOT_IMPLEMENTED:
        return "Not Implemented";
    case REST_STATUS_SERVICE_UNAVAILABLE:
        return "Service Unavailable";
    }

    assert(false);

    return "Unknown Status Code";
}
