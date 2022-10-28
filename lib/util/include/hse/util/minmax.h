/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2015-2022 Micron Technology, Inc.  All rights reserved.
 */

#ifndef HSE_UTIL_MINMAX_H
#define HSE_UTIL_MINMAX_H

#define min(x, y)                      \
    ({                                 \
        typeof(x) _min1 = (x);         \
        typeof(y) _min2 = (y);         \
        _min1 < _min2 ? _min1 : _min2; \
    })

#define max(x, y)                      \
    ({                                 \
        typeof(x) _max1 = (x);         \
        typeof(y) _max2 = (y);         \
        _max1 > _max2 ? _max1 : _max2; \
    })

#define min_t(type, x, y)                  \
    ({                                     \
        type __min1 = (x);                 \
        type __min2 = (y);                 \
        __min1 < __min2 ? __min1 : __min2; \
    })

#define max_t(type, x, y)                  \
    ({                                     \
        type __max1 = (x);                 \
        type __max2 = (y);                 \
        __max1 > __max2 ? __max1 : __max2; \
    })

/**
 * clamp_t - return a value clamped to a given range using a given type
 * @type: the type of variable to use
 * @val:  current value
 * @lo:   minimum allowable value
 * @hi:   maximum allowable value
 *
 * This macro does no typechecking and uses temporary variables of type
 * 'type' to make all the comparisons.
 */
#define clamp_t(type, val, min, max)           \
    ({                                         \
        type __val = (val);                    \
        type __min = (min);                    \
        type __max = (max);                    \
        __val = __val < __min ? __min : __val; \
        __val > __max ? __max : __val;         \
    })

#endif /* HSE_UTIL_MINMAX_H */
