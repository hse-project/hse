/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2020 Micron Technology, Inc.  All rights reserved.
 */

#include <hse_util/parse_num.h>

merr_t
parse_s64_range(const char *str, char **caller_endptr, s64 min_accept, s64 max_accept, s64 *result)
{
    char * endptr;
    merr_t err = 0;

    errno = 0;
    *result = strtol(str, &endptr, 0);
    if (errno) {
        err = merr(errno);
        goto done;
    }

    if (endptr == str) {
        /* empty string */
        *result = 0;
        return merr(EINVAL);
    }

    /* If caller didn't ask for endptr, then tolerate trailing whitespace */
    if (!caller_endptr)
        while (isspace(*endptr))
            endptr++;

    if (!caller_endptr && *endptr != '\0') {
        /* Caller did not ask for endptr and there are
         * extra chars after number --> EINVAL */
        err = merr(EINVAL);
        goto done;
    }

    if (caller_endptr)
        *caller_endptr = endptr;

done:
    /* all errors that are not ERANGE set result to 0 */
    if (err && merr_errno(err) != ERANGE) {
        *result = 0;
        return err;
    }

    /* Range errors: result is min or max of valid range */
    if (max_accept && *result > max_accept) {
        *result = max_accept;
        if (!err)
            err = merr(ERANGE);
    } else if (min_accept && *result < min_accept) {
        *result = min_accept;
        if (!err)
            err = merr(ERANGE);
    }

    return err;
}

merr_t
parse_u64_range(const char *str, char **caller_endptr, u64 min_accept, u64 max_accept, u64 *result)
{
    char * endptr;
    merr_t err = 0;

    errno = 0;
    *result = strtoul(str, &endptr, 0);
    if (errno) {
        err = merr(errno);
        goto done;
    }

    if (endptr == str) {
        /* empty string */
        *result = 0;
        return merr(EINVAL);
    }

    /* If caller didn't ask for endptr, then tolerate trailing whitespace */
    if (!caller_endptr)
        while (isspace(*endptr))
            endptr++;

    if (!caller_endptr && *endptr != '\0') {
        /* Caller did not ask for endptr and there are
         * extra chars after number --> EINVAL */
        err = merr(EINVAL);
        goto done;
    }

    if (caller_endptr)
        *caller_endptr = endptr;

done:
    /* all errors that are not ERANGE set result to 0 */
    if (err && merr_errno(err) != ERANGE) {
        *result = 0;
        return err;
    }

    /* Range errors: result is min or max of valid range */
    if (max_accept && *result > max_accept) {
        *result = max_accept;
        if (!err)
            err = merr(ERANGE);
    } else if (min_accept && *result < min_accept) {
        *result = min_accept;
        if (!err)
            err = merr(ERANGE);
    }

    return err;
}

merr_t
parse_size_range(const char *str, u64 min_accept, u64 max_accept, u64 *result)
{
    char * endptr;
    merr_t err;

    err = parse_u64_range(str, &endptr, 0, 0, result);

    if (err)
        goto done;

    /* Tolerate whitespace after digits */
    while (isspace(*endptr))
        endptr++;

    if (endptr[0]) {

        u64 scale;

        switch (tolower(*endptr)) {
            case 'k':
                scale = 1ull << 10;
                break;
            case 'm':
                scale = 1ull << 20;
                break;
            case 'g':
                scale = 1ull << 30;
                break;
            case 't':
                scale = 1ull << 40;
                break;
            case 'p':
                scale = 1ull << 50;
                break;
            case 'e':
                scale = 1ull << 60;
                break;
            default:
                err = merr(EINVAL);
                goto done;
        }

        endptr += 1;

        /* Tolerate trailing whitespace before NULL */
        while (isspace(*endptr))
            endptr++;
        if (*endptr) {
            err = merr(EINVAL);
            goto done;
        }

        /* Check overflow */
        if (*result > U64_MAX / scale) {
            *result = U64_MAX;
            err = merr(ERANGE);
            goto done;
        }

        *result *= scale;
    }

done:
    /* all errors that are not ERANGE set result to 0 */
    if (err && merr_errno(err) != ERANGE) {
        *result = 0;
        return err;
    }

    /* Range errors: result is min or max of valid range */
    if (max_accept && *result > max_accept) {
        *result = max_accept;
        if (!err)
            err = merr(ERANGE);
    } else if (min_accept && *result < min_accept) {
        *result = min_accept;
        if (!err)
            err = merr(ERANGE);
    }

    return err;
}
